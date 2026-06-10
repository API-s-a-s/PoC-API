/**
 * Estrategia para auditar las políticas de Context-Aware Access (Zero Trust)
 * Utiliza la Access Context Manager API para enumerar niveles de acceso.
 * Itera de forma paginada para asegurar la visibilidad completa del motor Zero Trust.
 */
class ContextAwareAccessStrategy extends ApiStrategy {
  constructor(policyId) {
    // 1. Matriz de configuración para inyectar la evaluación Zero Trust (ID-025)
    const configIDs = [
      { 
        id: "ID-025", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario025",
        riskKey: "riesgo025",
        scoreKey: "score025"
      }
    ];

    super("Context Aware Access (Zero Trust)", configIDs);
    
    // Validamos que el policyId haya sido suministrado (Por ejemplo: "accessPolicies/123456789")
    if (!policyId) {
      Logger.log("[ADVERTENCIA] No se suministró policyId a ContextAwareAccessStrategy.");
    }
    
    // Inyectamos el policyId recibido desde el main para construir el endpoint
    this.url = `https://accesscontextmanager.googleapis.com/v1/${policyId}/accessLevels`;
    this.category = "Identidad y autenticación";
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
    // 1. EVALUACIÓN DEFENSIVA EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR API] Context Aware Access Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo025: "Medio",
        score025: 2,
        comentario025: `Error de lectura en Access Context Manager: ${json.error.message}. Esto impide auditar la configuración de confianza cero (Zero Trust). Verifique que el policyId proporcionado exista en el proyecto GCP.`
      };
    }

    // 2. EXTRACCIÓN MASIVA (PAGINACIÓN OBLIGATORIA)
    let accessLevels = json.accessLevels || [];

    // Hidratación paginada para dominios con múltiples capas y jerarquías Zero Trust
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada en Access Context Manager. Extrayendo niveles restantes...");
      const allLevels = this.fetchPaginated(this.url, "accessLevels");
      if (allLevels) accessLevels = allLevels;
    }

    const totalLevels = accessLevels.length;

    // 3. LÓGICA DE NEGOCIO: FILTRADO DE REGLAS ZERO TRUST
    // El motor Zero Trust requiere la evaluación de vectores contextuales
    const zeroTrustLevels = accessLevels.filter(level => {
      if (level.basic && level.basic.conditions) {
        return level.basic.conditions.some(condicion => 
          condicion.ipSubnetworks || 
          condicion.regions || 
          condicion.devicePolicy
        );
      }
      return false;
    });

    // --- 4. APLICACIÓN DE MATRICES DE RIESGO ---
    let respuestaConcreta;
    let riesgo025, comentario025;

    if (zeroTrustLevels.length > 0) {
      // Caso 1: Existen niveles de acceso con restricciones de seguridad activas
      const porcentajeProtegido = Math.round((zeroTrustLevels.length / totalLevels) * 100);
      respuestaConcreta = `Habilitado (${zeroTrustLevels.length} niveles activos)`;
      riesgo025 = "Bajo";
      comentario025 = `CUMPLIMIENTO: Se detectaron ${zeroTrustLevels.length} niveles de acceso (del total de ${totalLevels}) que aplican condiciones restrictivas de arquitectura Zero Trust, evaluando vectores multidimensionales como subredes IP, geolocalización o postura criptográfica del dispositivo.`;

    } else if (totalLevels === 0) {
      // Caso 2: El JSON viene vacío (Infraestructura Legacy sin ACM)
      respuestaConcreta = "Deshabilitado (Vacío)";
      riesgo025 = "Alto";
      comentario025 = "VULNERABILIDAD CONFIGURADA: El motor de Access Context Manager no tiene definido ningún nivel de acceso (Access Level). El entorno opera bajo un modelo de red plana, sin restricciones contextuales de confianza cero.";

    } else {
      // Caso 3: Existen niveles de acceso pero ninguno cumple con criterios Zero Trust
      respuestaConcreta = "Deshabilitado (Sin restricciones válidas)";
      riesgo025 = "Alto";
      comentario025 = `VULNERABILIDAD CONFIGURADA: Existen ${totalLevels} niveles de acceso creados, pero ninguno aplica condiciones de seguridad válidas (como validación de IP de origen, geocercas o estado del dispositivo administrado).`;
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[RESULTADO ID-025] Motor Zero Trust (ACM): ${respuestaConcreta} | Riesgo: ${riesgo025}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: { totalAnalizados: totalLevels, payloadOmited: true },
      valorPrincipal: respuestaConcreta,
      comentario025: comentario025,
      riesgo025: riesgo025,
      score025: this.calcularScoreDeRiesgo(riesgo025)
    };
  }
}