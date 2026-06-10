/**
 * Estrategia para auditar la existencia de alias de dominio de prueba en Google Workspace.
 * Evalúa si existen dominios con el sufijo '.test-google-a.com' aprovisionados en el tenant.
 * Utiliza Admin SDK Directory API (v1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-092.
 */
class TestDomainAliasStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-092
    const configIDs = [
      { 
        id: "ID-092", 
        valueKey: "valorPrincipal", // Retornará la cantidad (entero) de dominios de prueba encontrados
        noteKey: "comentario092",
        riskKey: "riesgo092",
        scoreKey: "score092"
      }
    ];

    super("Test Domain Alias Audit", configIDs);
    
    // Endpoint directo a la API de Directory para listar los dominios del cliente
    this.url = `https://admin.googleapis.com/admin/directory/v1/customer/${customerId}/domains`;
    this.category = "Email y DNS";
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
      Logger.log(`[ERROR] Test Domain Alias Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo092: "Medio",
        score092: 2,
        comentario092: "Error de lectura, conectividad o permisos insuficientes en la API de Admin Directory que impide extraer el listado de dominios registrados en el tenant."
      };
    }

    let testDomainCount = 0;

    // 2. PARSEO DE DOMINIOS EN EL TENANT
    if (json.domains && json.domains.length > 0) {
      json.domains.forEach(domainObj => {
        const domainName = (domainObj.domainName || "").toLowerCase();
        
        // Filtramos para detectar el dominio de prueba de Google Workspace u otros sospechosos
        if (domainName.endsWith('.test-google-a.com')) {
          testDomainCount++;
        }
      });
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo092, comentario092;

    if (testDomainCount === 0) {
      // Caso 1: No hay alias de prueba de Google (Seguro)
      riesgo092 = "Bajo";
      comentario092 = "No se encontraron alias de dominio de prueba predeterminados (como *.test-google-a.com). Esto minimiza la superficie de ataque y previene que actores maliciosos intenten evadir políticas de enrutamiento o esquemas de Single Sign-On (SSO) empleando el dominio de pruebas.";
    } else {
      // Caso 2: Existen dominios de prueba (Riesgo Medio)
      riesgo092 = "Medio";
      comentario092 = "Indica la cantidad de alias de dominio de prueba (ej. *.test-google-a.com) detectados como activos en el entorno. Aunque Google los aprovisiona por defecto para procesos de migración, se recomienda eliminarlos si no están en uso activo para evitar vectores de bypass de seguridad.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Test Domain Alias Audit: Se detectaron ${testDomainCount} dominios de prueba. | Riesgo: ${riesgo092}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: testDomainCount,
      comentario092: comentario092,
      riesgo092: riesgo092,
      score092: this.calcularScoreDeRiesgo(riesgo092)
    };
  }
}