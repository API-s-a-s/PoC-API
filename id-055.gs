/**
 * Estrategia para auditar la lista de aplicaciones permitidas del Marketplace.
 * Evalúa cuántas apps externas tienen permiso explícito de instalación.
 * Utiliza Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-055
 */
class MarketplaceAllowlistStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-055 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-055", 
        valueKey: "valorPrincipal", // Entregará el número entero de aplicaciones permitidas
        noteKey: "comentario055",
        riskKey: "riesgo055",
        scoreKey: "score055"
      }
    ];

    super("Marketplace Allowlist Audit", configIDs);
    const filter = `customer=="customers/${customerId}" && setting.type=="workspace_marketplace.apps_allowlist"`;
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
      Logger.log(`[ERROR] Marketplace Allowlist: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo055: "Medio",
        score055: 2,
        comentario055: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide extraer y auditar técnicamente la lista de aplicaciones de confianza del Marketplace."
      };
    }

    let allowedCount = 0;

    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Buscamos el nodo de la lista permitida tolerando la estructura de la API
      const allowlistNode = setting.workspaceMarketplaceAppsAllowlist || {};
      const apps = allowlistNode.apps || [];
      
      allowedCount = apps.length;
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo055, comentario055;

    if (allowedCount === 0) {
      // Caso 1: No hay apps permitidas en la lista
      riesgo055 = "Bajo";
      comentario055 = "La consulta a la API indica que no existen aplicaciones de terceros configuradas en la lista de confianza (Allowlist) de Google Workspace Marketplace; ninguna aplicación externa está explícitamente permitida para instalación por los usuarios.";
    } else {
      // Caso 2: Existen apps en la allowlist
      riesgo055 = "Medio";
      comentario055 = "Indica la cantidad exacta de aplicaciones de terceros que se encuentran agregadas a la lista de confianza (Allowlist) de Google Workspace Marketplace, lo que autoriza a los usuarios finales a instalarlas de forma autónoma.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Marketplace Allowlist Audit: Se detectaron ${allowedCount} aplicaciones en la lista de permitidas (Allowlist). | Riesgo: ${riesgo055}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: allowedCount,
      comentario055: comentario055,
      riesgo055: riesgo055,
      score055: this.calcularScoreDeRiesgo(riesgo055)
    };
  }
}