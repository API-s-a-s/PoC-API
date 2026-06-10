/**
 * Estrategia para auditar las Reglas de Cumplimiento de Archivos Adjuntos en Gmail.
 * Evalúa cuántas restricciones explícitas existen sobre extensiones, tipos y contenido de adjuntos.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-084.
 */
class GmailAttachmentComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-084
    const configIDs = [
      { 
        id: "ID-084", 
        valueKey: "valorPrincipal", // Retornará el número entero de reglas configuradas
        noteKey: "comentario084",
        riskKey: "riesgo084",
        scoreKey: "score084"
      }
    ];

    super("Gmail Attachment Compliance Audit", configIDs);
    
    // Aplicamos el filtro exacto de la API para 'gmail.attachment_compliance'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.attachment_compliance"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Email y DNS";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Attachment Compliance Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo084: "Medio",
        score084: 2,
        comentario084: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente las reglas de cumplimiento de archivos adjuntos."
      };
    }

    let rulesCount = 0;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const complianceNode = setting.gmailAttachmentCompliance || setting.attachmentCompliance || setting;
      
      // Buscamos el arreglo de reglas (extensiones, tipos MIME, etc.)
      const rules = complianceNode.rules || complianceNode.settingRules || complianceNode.complianceRules || [];
      rulesCount = rules.length;
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo084, comentario084;

    if (rulesCount === 0) {
      // Caso 1: Cero reglas de adjuntos (Riesgo Alto por falta de controles perimetrales)
      riesgo084 = "Alto";
      comentario084 = "No se encontraron reglas de cumplimiento de archivos adjuntos (Attachment Compliance) configuradas. La organización no está restringiendo de manera personalizada la entrada o salida de extensiones de archivos riesgosas, dejando el entorno vulnerable a la infiltración de malware dirigido o a la exfiltración de datos no autorizada a través de adjuntos permitidos.";
    } else {
      // Caso 2: Existen reglas de adjuntos configuradas (Seguro / Maduro)
      riesgo084 = "Bajo";
      comentario084 = "Indica la cantidad de reglas activas de cumplimiento de archivos adjuntos. La organización cuenta con políticas personalizadas que inspeccionan, bloquean o ponen en cuarentena correos en función de los tipos MIME, extensiones o características de los archivos adjuntos, mitigando proactivamente vectores de infección por malware y fugas de datos.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Attachment Compliance Audit: Se detectaron ${rulesCount} reglas sobre archivos adjuntos. | Riesgo: ${riesgo084}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: rulesCount,
      comentario084: comentario084,
      riesgo084: riesgo084,
      score084: this.calcularScoreDeRiesgo(riesgo084)
    };
  }
}