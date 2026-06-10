/**
 * Estrategia para auditar la configuración de Seguridad de Archivos Adjuntos en Gmail (Control Duplicado/Alterno).
 * Evalúa si las protecciones avanzadas contra malware y ransomware en adjuntos están activas.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-073.
 */
class GmailAttachmentSafetyId073Strategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-073
    const configIDs = [
      { 
        id: "ID-073", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario073",
        riskKey: "riesgo073",
        scoreKey: "score073"
      }
    ];

    super("Gmail Attachment Safety Audit (ID-073)", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.email_attachment_safety'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.email_attachment_safety"`;
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
      Logger.log(`[ERROR] Attachment Safety Audit (ID-073): ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo073: "Medio",
        score073: 2,
        comentario073: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si las protecciones avanzadas contra archivos adjuntos maliciosos están habilitadas."
      };
    }

    let isAttachmentSafetyEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const safetyNode = setting.gmailEmailAttachmentSafety || setting.emailAttachmentSafety || setting;
      
      // Verificamos si la protección de adjuntos está activa explícitamente
      if (safetyNode.enableEmailAttachmentSafety === true || 
          safetyNode.enable_email_attachment_safety === true || 
          (safetyNode.state && safetyNode.state.toUpperCase() === 'ENABLED')) {
        isAttachmentSafetyEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo073, comentario073;

    if (isAttachmentSafetyEnabled) {
      // Caso 1: Protección de adjuntos habilitada (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo073 = "Bajo";
      comentario073 = "La protección avanzada de archivos adjuntos (Email Attachment Safety) se encuentra habilitada. El entorno aplica barreras heurísticas y entornos aislados (sandboxing) para detectar y bloquear proactivamente la entrega de correos con malware, ransomware o scripts ejecutables no confiables.";
    } else {
      // Caso 2: Protección de adjuntos deshabilitada (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo073 = "Alto";
      comentario073 = "La protección avanzada contra archivos adjuntos maliciosos se encuentra deshabilitada o degradada. Esta configuración expone severamente a los usuarios frente a ataques de ingeniería social y distribución de malware (como ransomware o troyanos) camuflados en documentos de uso cotidiano.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Attachment Safety Audit (ID-073): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo073}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario073: comentario073,
      riesgo073: riesgo073,
      score073: this.calcularScoreDeRiesgo(riesgo073)
    };
  }
}