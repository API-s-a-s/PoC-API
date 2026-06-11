/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Cloud.
 * Verifica si hay servicios de GCP restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API en memoria
 */
class GoogleCloudApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-045", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario045",
        riskKey: "riesgo045",
        scoreKey: "score045"
      }
    ];

    super("Google Cloud API Controls Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && p.setting.type === "api_controls.google_cloud");

    let restrictedCount = 0;
    let totalServices = 0;
    let restrictedServicesList = [];

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.google_cloud");
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        if (configNode.googleCloud || configNode.google_cloud) {
          const gcNode = configNode.googleCloud || configNode.google_cloud;
          const services = gcNode.services || [];
          totalServices = services.length;
          
          services.forEach(s => {
            if (s.accessLevel === 'RESTRICTED' || s.access_level === 'RESTRICTED') {
              restrictedCount++;
              restrictedServicesList.push(s);
            }
          });
        }
      }
    }

    let riesgo045, comentario045;
    let rawOutput = JSON.stringify(restrictedServicesList);

    if (restrictedCount === 0) {
      riesgo045 = "Alto";
      rawOutput = "0%";
      comentario045 = `${restrictedCount} de ${totalServices} servicios GCP: Ningún servicio se encuentra configurado con nivel de acceso restringido, lo que permite acceso ilimitado a scopes de GCP para aplicaciones de terceros.`;
    } else {
      riesgo045 = "Medio";
      comentario045 = `${restrictedCount} de ${totalServices} servicios GCP: Se encontraron restringidos para aplicaciones de terceros.`;
    }

    return {
      name: this.name,
      valorPrincipal: rawOutput, 
      comentario045: comentario045,
      riesgo045: riesgo045,
      score045: this.calcularScoreDeRiesgo(riesgo045)
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo045: "Medio", score045: 2, comentario045: msg };
  }
}