/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Services.
 * Verifica qué servicios están restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-044
 */
class GoogleServicesApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-044 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-044", 
        valueKey: "valorPrincipal", // Entregará el número entero de servicios restringidos
        noteKey: "comentario044",
        riskKey: "riesgo044",
        scoreKey: "score044"
      }
    ];

    super("Google Services API Controls Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="api_controls.google_services"`;
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
      Logger.log(`[ERROR] API Controls Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo044: "Medio",
        score044: 2,
        comentario044: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente la configuración de controles de acceso a las APIs de los servicios de Google Workspace."
      };
    }

    let restrictedCount = 0;
    let totalServices = 0;

    if (json.policies && json.policies.length > 0) {
      const policy = json.policies[0];
      
      // Validamos que la estructura interna exista para evitar errores de lectura
      if (policy.setting && policy.setting.googleServices) {
        const services = policy.setting.googleServices.services || [];
        totalServices = services.length;
        
        // Contamos exactamente cuántos servicios tienen el nivel de acceso RESTRICTED
        restrictedCount = services.filter(s => s.accessLevel === 'RESTRICTED').length;
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo044, comentario044;

    if (restrictedCount === 0) {
      // Caso 1: Ningún servicio base está restringido
      riesgo044 = "Alto";
      comentario044 = "La consulta a la API indica que ningún servicio base de Google Workspace se encuentra configurado con nivel de acceso restringido, lo que permite a las aplicaciones de terceros solicitar acceso a los alcances (scopes) de los usuarios sin barreras de autorización explícitas.";
    } else {
      // Caso 2: Al menos un servicio base está restringido
      riesgo044 = "Medio";
      comentario044 = "Indica la cantidad exacta de servicios base de Google Workspace que han sido configurados con un nivel de acceso explícitamente restringido (RESTRICTED) para aplicaciones de terceros.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] API Controls Audit: ${restrictedCount} de ${totalServices} servicios base están configurados como RESTRINGIDOS. | Riesgo: ${riesgo044}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: restrictedCount, 
      comentario044: comentario044,
      riesgo044: riesgo044,
      score044: this.calcularScoreDeRiesgo(riesgo044)
    };
  }
}