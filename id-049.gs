/**
 * Estrategia para auditar el uso de Domain-Wide Delegation (DWD).
 * Busca eventos de 'allow_token_request' en los registros de auditoría.
 * Utiliza Admin SDK Reports API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-049
 */
class DwdTokenRequestAuditStrategy extends ApiStrategy {
  constructor() { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-049 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-049", 
        valueKey: "valorPrincipal", // Entregará el número entero de eventos DWD
        noteKey: "comentario049",
        riskKey: "riesgo049",
        scoreKey: "score049"
      }
    ];

    super("DWD Token Request Audit", configIDs);
    
    // No requiere customerId en la URL porque usa 'users/all'
    this.url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/access_evaluation?eventName=allow_token_request`;
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
      Logger.log(`[ERROR] Reports API (DWD): ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo049: "Medio",
        score049: 2,
        comentario049: "Error de lectura, conectividad o permisos insuficientes en la API Reports que impide consultar los registros de actividad y contabilizar los eventos de delegación de dominio."
      };
    }

    let dwdEventCount = 0;

    // Navegamos por la estructura de los logs: items -> events -> parameters
    if (json.items && json.items.length > 0) {
      json.items.forEach(item => {
        if (item.events) {
          item.events.forEach(event => {
            if (event.parameters) {
              // Buscamos si este evento específico fue gatillado por DWD
              const configSource = event.parameters.find(p => p.name === 'configuration_source');
              if (configSource && configSource.value === 'DOMAIN_WIDE_DELEGATION') {
                dwdEventCount++;
              }
            }
          });
        }
      });
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo049, comentario049;

    if (dwdEventCount === 0) {
      // Caso 1: No hay eventos de DWD
      riesgo049 = "Bajo";
      comentario049 = "La bitácora de auditoría no registra eventos recientes de peticiones de tokens de acceso mediante delegación de todo el dominio (Domain-Wide Delegation).";
    } else {
      // Caso 2: Existen eventos DWD
      riesgo049 = "Alto";
      comentario049 = "Indica la cantidad exacta de eventos recientes en la bitácora de auditoría donde se evaluaron y permitieron peticiones de tokens de acceso utilizando el método de delegación de todo el dominio (Domain-Wide Delegation).";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] DWD Audit: Se detectaron ${dwdEventCount} peticiones de tokens de delegación de dominio. | Riesgo: ${riesgo049}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: dwdEventCount, 
      comentario049: comentario049,
      riesgo049: riesgo049,
      score049: this.calcularScoreDeRiesgo(riesgo049)
    };
  }
}