/**
 * Estrategia para auditar la edad de las claves de una Cuenta de Servicio en GCP.
 * Evalúa si las claves gestionadas por usuarios tienen más de 90 días.
 * Utiliza Google Cloud IAM API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-052
 */
class ServiceAccountKeyAgeStrategy extends ApiStrategy {
  constructor(projectId, serviceAccountId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-052 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-052", 
        valueKey: "valorPrincipal", // Entregará el número entero de claves obsoletas (> 90 días)
        noteKey: "comentario052",
        riskKey: "riesgo052",
        scoreKey: "score052"
      }
    ];

    super("GCP Service Account Key Age Audit", configIDs);
    this.url = `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${serviceAccountId}/keys`;
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
      Logger.log(`[ERROR] IAM Key Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo052: "Medio",
        score052: 2,
        comentario052: "Error de lectura, conectividad o permisos insuficientes en la API IAM de Google Cloud que impide extraer el listado de claves y calcular su antigüedad."
      };
    }

    let staleKeysCount = 0;
    let userManagedCount = 0;
    const now = new Date();

    if (json.keys && json.keys.length > 0) {
      json.keys.forEach(key => {
        // Solo nos interesan las claves descargadas por usuarios, no las del sistema
        if (key.keyType === 'USER_MANAGED') {
          userManagedCount++;
          
          if (key.validAfterTime) {
            const creationDate = new Date(key.validAfterTime);
            // Calculamos la diferencia en días
            const diffTime = Math.abs(now - creationDate);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
            
            // Si la clave tiene más de 90 días, incrementamos el contador de riesgo
            if (diffDays > 90) {
              staleKeysCount++;
            }
          }
        }
      });
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo052, comentario052;

    if (staleKeysCount === 0) {
      // Caso 1: No hay claves gestionadas por el usuario con más de 90 días
      riesgo052 = "Bajo";
      comentario052 = "La consulta a la API indica que no existen claves de cuenta de servicio gestionadas por el usuario (USER_MANAGED) con una antigüedad superior a 90 días desde su fecha de creación.";
    } else {
      // Caso 2: Existen claves obsoletas (más de 90 días)
      riesgo052 = "Alto";
      comentario052 = "Indica la cantidad exacta de claves de cuenta de servicio gestionadas por el usuario cuya antigüedad de creación supera los 90 días, evidenciando la ausencia de una rotación criptográfica reciente.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Service Account Key Audit: Se evaluaron ${userManagedCount} claves de usuario. Se detectaron ${staleKeysCount} claves con más de 90 días de antigüedad. | Riesgo: ${riesgo052}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: staleKeysCount,
      comentario052: comentario052,
      riesgo052: riesgo052,
      score052: this.calcularScoreDeRiesgo(riesgo052)
    };
  }
}