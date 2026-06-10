/**
 * Estrategia para auditar la configuración de instalación de Marketplace.
 * Evalúa si los usuarios pueden instalar aplicaciones libremente o de forma restringida.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-053
 */
class MarketplaceInstallPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-053 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-053", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario053",
        riskKey: "riesgo053",
        scoreKey: "score053"
      }
    ];

    super("Marketplace Install Policy Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="workspace_marketplace.apps_access_options"`;
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
      Logger.log(`[ERROR] Marketplace Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo053: "Medio",
        score053: 2,
        comentario053: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide extraer y auditar la directiva de instalación de aplicaciones del Marketplace."
      };
    }

    let isSecure = false; // Por seguridad, asumimos riesgo (Deshabilitado) hasta demostrar lo contrario

    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Convertimos todo el nodo de configuración a texto plano en mayúsculas para un análisis robusto
      const settingStr = JSON.stringify(setting).toUpperCase();

      // Evaluamos si el nivel de acceso denota restricción o bloqueo
      if (settingStr.includes('"ACCESSLEVEL":"RESTRICTED"') || 
          settingStr.includes('"ACCESS_LEVEL":"RESTRICTED"') ||
          settingStr.includes('RESTRICTED') || 
          settingStr.includes('BLOCKED')) {
        isSecure = true;
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    // Habilitado = El control de seguridad está activo (instalaciones restringidas)
    // Deshabilitado = El control está inactivo (pueden instalar libremente)
    let respuestaConcreta;
    let riesgo053, comentario053;

    if (isSecure) {
      // Caso 1: Instalaciones restringidas/bloqueadas
      respuestaConcreta = "Habilitado";
      riesgo053 = "Bajo";
      comentario053 = "La política de acceso a Google Workspace Marketplace se encuentra configurada con parámetros restrictivos o de bloqueo, impidiendo que los usuarios finales instalen aplicaciones de terceros de forma autónoma e ilimitada.";
    } else {
      // Caso 2: Instalaciones libres (no restringidas)
      respuestaConcreta = "Deshabilitado";
      riesgo053 = "Alto";
      comentario053 = "La política de acceso a Google Workspace Marketplace carece de restricciones explícitas, lo que permite a los usuarios finales la instalación libre e ilimitada de aplicaciones de terceros en el dominio.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Marketplace Policy Audit: Control de restricciones -> ${respuestaConcreta} | Riesgo: ${riesgo053}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario053: comentario053,
      riesgo053: riesgo053,
      score053: this.calcularScoreDeRiesgo(riesgo053)
    };
  }
}