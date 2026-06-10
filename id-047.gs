/**
 * Estrategia para auditar la confianza de las aplicaciones propiedad del dominio.
 * Evalúa si las apps internas tienen acceso confiable por defecto.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-047
 */
class InternalAppsTrustStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-047 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-047", 
        valueKey: "valorPrincipal", // "Habilitado", "Deshabilitado" o JSON crudo
        noteKey: "comentario047",
        riskKey: "riesgo047",
        scoreKey: "score047"
      }
    ];

    super("Internal Apps Trust Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="api_controls.internal_apps"`;
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
      Logger.log(`[ERROR] Internal Apps Control: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo047: "Medio",
        score047: 2,
        comentario047: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente la política de confianza asignada a las aplicaciones internas del dominio."
      };
    }

    const policies = json.policies || [];
    let isTrustedByDefault = false;
    let existePoliticaExplicita = false;

    if (policies.length > 0) {
      existePoliticaExplicita = true;
      const setting = policies[0].setting || {};
      
      // Buscamos la propiedad tolerando variaciones de la API beta
      const configNode = setting.internalApps || setting;
      
      if (configNode.trustInternalApps === true || configNode.trust_internal_apps === true) {
        isTrustedByDefault = true;
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo047, comentario047;

    if (isTrustedByDefault) {
      // Caso 1: Las apps internas son confiables por defecto (Riesgo detectado)
      respuestaConcreta = "Habilitado";
      riesgo047 = "Alto";
      comentario047 = "La política de controles de API se encuentra configurada para confiar de manera predeterminada en todas las aplicaciones desarrolladas internamente y propiedad del dominio, permitiéndoles el acceso a los datos sin requerir autorización granular explícita.";
    } else if (!existePoliticaExplicita) {
      // Caso 2: El JSON viene vacío, no hay política configurada
      respuestaConcreta = "Deshabilitado";
      riesgo047 = "Medio";
      comentario047 = "La consola de administración no cuenta con ninguna política explícita configurada referente a la confianza predeterminada de las aplicaciones propiedad del dominio.";
    } else {
      // Caso 3: La política existe pero indica que NO son confiables por defecto (Seguro)
      // Volcamos el JSON para inspección técnica manual
      respuestaConcreta = JSON.stringify(json);
      riesgo047 = "Bajo";
      comentario047 = "Existe una directiva técnica configurada que deniega explícitamente la confianza automática a las aplicaciones internas, obligando a que cada aplicación propiedad del dominio sea autorizada y evaluada de forma individual.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Internal Apps Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo047}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario047: comentario047,
      riesgo047: riesgo047,
      score047: this.calcularScoreDeRiesgo(riesgo047)
    };
  }
}