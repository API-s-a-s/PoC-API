/**
 * Estrategia para auditar la configuración del Modo Confidencial de Gmail.
 * Evalúa si los usuarios pueden enviar correos con restricciones de reenvío/descarga.
 * Utiliza Cloud Identity API (v1beta1)
 * Lógica de negocio inferida y textos inyectados directamente para el ID-060.
 */
class GmailConfidentialModeStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz (Asignamos ID-060 secuencialmente)
    const configIDs = [
      { 
        id: "ID-060", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario060",
        riskKey: "riesgo060",
        scoreKey: "score060"
      }
    ];

    super("Gmail Confidential Mode Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.confidential_mode"`;
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
      Logger.log(`[ERROR] Gmail Confidential Mode: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo060: "Medio",
        score060: 2,
        comentario060: "Error de conectividad, lectura o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el Modo Confidencial de Gmail está habilitado en el tenant."
      };
    }

    let isConfidentialModeEnabled = false;

    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Manejamos las posibles variaciones de la API beta para el nodo de configuración
      const confNode = setting.gmailConfidentialMode || setting.confidentialMode || setting;
      
      // Verificamos el booleano en formato camelCase o snake_case
      if (confNode.enableConfidentialMode === true || confNode.enable_confidential_mode === true) {
        isConfidentialModeEnabled = true;
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo060, comentario060;

    if (isConfidentialModeEnabled) {
      // Caso 1: El Modo Confidencial está habilitado
      respuestaConcreta = "Habilitado";
      riesgo060 = "Bajo";
      comentario060 = "El Modo Confidencial de Gmail se encuentra activo en el dominio, dotando a los usuarios de la capacidad de aplicar restricciones de reenvío, impedir descargas y configurar fechas de caducidad en sus correos, lo que mitiga sustancialmente la fuga de información sensible.";
    } else {
      // Caso 2: El Modo Confidencial está deshabilitado
      respuestaConcreta = "Deshabilitado";
      riesgo060 = "Medio";
      comentario060 = "El Modo Confidencial de Gmail se encuentra inactivo. Los usuarios no pueden aplicar controles de expiración o restricciones de descarga a los correos electrónicos que envían, lo que incrementa el riesgo de exposición, copia o reenvío no autorizado de datos corporativos.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Gmail Confidential Mode Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo060}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario060: comentario060,
      riesgo060: riesgo060,
      score060: this.calcularScoreDeRiesgo(riesgo060)
    };
  }
}