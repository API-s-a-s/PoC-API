/**
 * Estrategia para auditar el control de acceso a la API de Google Cloud Platform.
 * Verifica si el servicio de GCP está restringido para aplicaciones de terceros.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-045
 */
class GoogleCloudApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-045 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-045", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario045",
        riskKey: "riesgo045",
        scoreKey: "score045"
      }
    ];

    super("Google Cloud API Controls Audit", configIDs);
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
      Logger.log(`[ERROR] Cloud API Controls: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo045: "Medio",
        score045: 2,
        comentario045: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente la configuración de controles de acceso a las APIs de Google Cloud Platform."
      };
    }

    let isRestricted = false;

    if (json.policies && json.policies.length > 0) {
      const policy = json.policies[0];
      
      // Validamos la estructura para evitar errores de referencia
      if (policy.setting && policy.setting.googleServices) {
        const services = policy.setting.googleServices.services || [];
        
        // Buscamos específicamente la configuración del servicio de GCP
        const gcpService = services.find(s => s.serviceId === 'google_cloud_platform');
        
        // Si existe y su nivel es RESTRICTED, el control de seguridad está activo
        if (gcpService && gcpService.accessLevel === 'RESTRICTED') {
          isRestricted = true;
        }
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo045, comentario045;

    if (isRestricted) {
      // Caso 1: El servicio de GCP está restringido
      respuestaConcreta = "Habilitado";
      riesgo045 = "Bajo";
      comentario045 = "El servicio de Google Cloud Platform se encuentra explícitamente configurado con un nivel de acceso restringido (RESTRICTED), bloqueando el acceso a sus alcances (scopes) por parte de aplicaciones de terceros.";
    } else {
      // Caso 2: El servicio no está restringido
      respuestaConcreta = "Deshabilitado";
      riesgo045 = "Alto";
      comentario045 = "El servicio de Google Cloud Platform no cuenta con un nivel de acceso restringido, lo que permite que aplicaciones de terceros puedan solicitar y obtener acceso a los alcances y recursos de GCP de los usuarios sin barreras de autorización explícitas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Cloud API Audit: Restricción a GCP -> ${respuestaConcreta} | Riesgo: ${riesgo045}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario045: comentario045,
      riesgo045: riesgo045,
      score045: this.calcularScoreDeRiesgo(riesgo045)
    };
  }
}