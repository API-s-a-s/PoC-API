/**
 * Estrategia para auditar el mensaje de visualización personalizado.
 * Evalúa si existe un mensaje corporativo cuando se bloquea el acceso a una App.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-048
 */
class CustomUserMessageApiStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-048 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-048", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario048",
        riskKey: "riesgo048",
        scoreKey: "score048"
      }
    ];

    super("Custom User Message API Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="api_controls.custom_user_message"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Integración de aplicaciones";
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
      Logger.log(`[ERROR] Custom User Message: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo048: "Medio",
        score048: 2,
        comentario048: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide extraer y auditar técnicamente la configuración del mensaje de visualización personalizado."
      };
    }

    let customMessage = "";

    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Buscamos la propiedad del mensaje tolerando variaciones de la API beta
      const configNode = setting.customUserMessage || setting;
      customMessage = configNode.error_text || configNode.errorMessage || configNode.customMessage || "";
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo048, comentario048;

    if (customMessage && customMessage.trim() !== "") {
      // Caso 1: Hay un mensaje corporativo configurado
      respuestaConcreta = "Habilitado";
      riesgo048 = "Bajo";
      comentario048 = "Existe una directiva con un mensaje corporativo personalizado configurado que se mostrará a los usuarios cuando se bloquee su intento de acceso a aplicaciones de terceros no autorizadas.";
    } else {
      // Caso 2: No hay políticas o el mensaje está vacío (usa el de Google por defecto)
      respuestaConcreta = "Deshabilitado";
      riesgo048 = "Medio";
      comentario048 = "No existe un mensaje corporativo personalizado configurado en la consola; el sistema utilizará el mensaje de error estándar y predeterminado de Google cuando se bloquee el acceso a una aplicación.";
    }

    // Trazabilidad técnica para la consola del auditor
    let snippet = customMessage.length > 60 ? customMessage.substring(0, 60) + "..." : customMessage;
    Logger.log(`[LOG] Custom Message Audit: Resultado -> ${respuestaConcreta}. | Riesgo: ${riesgo048}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario048: comentario048,
      riesgo048: riesgo048,
      score048: this.calcularScoreDeRiesgo(riesgo048)
    };
  }
}