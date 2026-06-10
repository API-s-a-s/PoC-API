/**
 * Estrategia para auditar las listas de remitentes aprobados (Spam Override Lists) de Gmail.
 * Evalúa cuántos remitentes o dominios tienen permitido saltarse el filtro de spam.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-078.
 */
class GmailSpamOverrideListsStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-078
    const configIDs = [
      { 
        id: "ID-078", 
        valueKey: "valorPrincipal", // Retornará el número entero de remitentes aprobados
        noteKey: "comentario078",
        riskKey: "riesgo078",
        scoreKey: "score078"
      }
    ];

    super("Gmail Spam Override Lists Audit", configIDs);
    
    // Aplicamos el filtro exacto de la API para 'gmail.spam_override_lists'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.spam_override_lists"`;
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
      Logger.log(`[ERROR] Spam Override Lists Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo078: "Medio",
        score078: 2,
        comentario078: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente la lista de remitentes aprobados que evaden los filtros de spam."
      };
    }

    let overrideCount = 0;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const overrideNode = setting.gmailSpamOverrideLists || setting.spamOverrideLists || setting;
      
      // Buscamos el arreglo de direcciones o dominios exentos
      const senders = overrideNode.approvedSenders || overrideNode.addresses || overrideNode.senders || [];
      overrideCount = senders.length;
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo078, comentario078;

    if (overrideCount === 0) {
      // Caso 1: Lista vacía (Seguro)
      riesgo078 = "Bajo";
      comentario078 = "La lista de remitentes aprobados (Spam Override Lists) se encuentra vacía. No existen dominios ni direcciones de correo con excepciones configuradas para saltarse el motor antispam de Google, lo que garantiza que todo el tráfico entrante sea evaluado de manera imparcial por las heurísticas de seguridad.";
    } else {
      // Caso 2: Existen remitentes exentos (Riesgo Medio)
      riesgo078 = "Medio";
      comentario078 = "Indica la cantidad de remitentes o dominios configurados explícitamente en la lista de aprobados (Spam Override). Estos remitentes evaden las validaciones de reputación del filtro de spam, lo que requiere auditoría periódica para asegurar que no se estén exponiendo las bandejas de entrada a cuentas externas comprometidas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spam Override Lists Audit: Se detectaron ${overrideCount} remitentes exentos del filtro de spam. | Riesgo: ${riesgo078}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: overrideCount,
      comentario078: comentario078,
      riesgo078: riesgo078,
      score078: this.calcularScoreDeRiesgo(riesgo078)
    };
  }
}