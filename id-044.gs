/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Services.
 * Verifica qué servicios están restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API en memoria
 */
class GoogleServicesApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-044", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario044",
        riskKey: "riesgo044",
        scoreKey: "score044"
      }
    ];

    super("Google Services API Controls Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && p.setting.type === "api_controls.google_services");

    let restrictedCount = 0;
    let totalServices = 0;
    let isDriveRestricted = false;
    let isGmailRestricted = false;

    let restrictedServicesList = [];

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.google_services");
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        if (configNode.googleServices || configNode.google_services) {
          const gsNode = configNode.googleServices || configNode.google_services;
          const services = gsNode.services || [];
          totalServices = services.length;
          
          services.forEach(s => {
            if (s.accessLevel === 'RESTRICTED' || s.access_level === 'RESTRICTED') {
              restrictedCount++;
              restrictedServicesList.push(s);
              const serviceName = (s.service || "").toLowerCase();
              if (serviceName.includes("drive")) isDriveRestricted = true;
              if (serviceName.includes("gmail") || serviceName.includes("mail")) isGmailRestricted = true;
            }
          });
        }
      }
    }

    let riesgo044, comentario044;
    let rawOutput = JSON.stringify(restrictedServicesList);

    if (restrictedCount === 0) {
      riesgo044 = "Alto";
      rawOutput = "0%";
      comentario044 = `${restrictedCount} de ${totalServices} servicios: La política indica que ningún servicio base se encuentra restringido, permitiendo acceso ilimitado a scopes de usuarios.`;
    } else {
      if (isDriveRestricted && isGmailRestricted) {
        riesgo044 = "Bajo";
        comentario044 = `${restrictedCount} de ${totalServices} servicios: Se encontraron restringidos correctamente (incluyendo los de mayor riesgo como Drive y Gmail).`;
      } else {
        riesgo044 = "Medio";
        comentario044 = `${restrictedCount} de ${totalServices} servicios: Están restringidos, pero servicios de alto riesgo (Drive y/o Gmail) NO están explícitamente restringidos.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: rawOutput, 
      comentario044: comentario044,
      riesgo044: riesgo044,
      score044: this.calcularScoreDeRiesgo(riesgo044)
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo044: "Medio", score044: 2, comentario044: msg };
  }
}