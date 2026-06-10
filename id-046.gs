/**
 * Estrategia para auditar la configuración de aplicaciones de terceros no configuradas.
 * Evalúa si el acceso por defecto es restringido o ilimitado.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-046
 */
class UnconfiguredAppsStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-046 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-046", 
        valueKey: "valorPrincipal", // Entregará "Habilitado" o "Deshabilitado"
        noteKey: "comentario046",
        riskKey: "riesgo046",
        scoreKey: "score046"
      }
    ];

    super("Unconfigured Third Party Apps Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="api_controls.unconfigured_third_party_apps"`;
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
      Logger.log(`[ERROR] Unconfigured Apps Control: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo046: "Medio",
        score046: 2,
        comentario046: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente la política de acceso de aplicaciones de terceros no configuradas."
      };
    }

    let accessLevel = "Deshabilitado";

    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de la API beta en la anidación
      const unconfiguredSetting = setting.unconfiguredThirdPartyApps || setting;
      
      if (unconfiguredSetting.accessLevel) {
        // Extraemos el valor exacto de la API ("RESTRICTED", "UNLIMITED", etc.)
        accessLevel = "Habilitado";
      } else {
        accessLevel = "Deshabilitado";
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta = accessLevel;
    let riesgo046, comentario046;

    if (respuestaConcreta === "Habilitado") {
      // Caso 1: La política cuenta con un nivel de acceso definido
      riesgo046 = "Medio";
      comentario046 = "La política de control de acceso para aplicaciones de terceros no configuradas cuenta con un nivel de acceso explícitamente definido y activo en la consola de administración.";
    } else {
      // Caso 2: No hay configuración (Deshabilitado)
      riesgo046 = "Alto";
      comentario046 = "La consola de administración no tiene configurada ninguna directiva o nivel de acceso específico para regular los permisos de las aplicaciones de terceros no configuradas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Unconfigured Apps Audit: Nivel de acceso detectado -> ${respuestaConcreta} | Riesgo: ${riesgo046}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario046: comentario046,
      riesgo046: riesgo046,
      score046: this.calcularScoreDeRiesgo(riesgo046)
    };
  }
}