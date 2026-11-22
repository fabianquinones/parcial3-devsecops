import groovy.transform.Field

@Field Map ESTADO = [:]

// Funciones auxiliares
def run(String cmd) {
    if (isUnix()) { sh cmd } else { bat cmd }
}

def runStatus(String cmd) {
    return isUnix() ? sh(script: cmd, returnStatus: true) : bat(script: cmd, returnStatus: true)
}

def runOut(String cmd) {
    return (isUnix() ? sh(script: cmd, returnStdout: true) : bat(script: "@${cmd}", returnStdout: true)).trim()
}

def ruta(String rel) {
    return isUnix() ? "${env.WORKSPACE}/${rel}" : "${env.WORKSPACE}\\${rel.replace('/', '\\')}"
}

def control(String nombre, String cmd) {
    int rc = runStatus(cmd)
    if (rc == 0) {
        ESTADO[nombre] = 'OK'
    } else {
        ESTADO[nombre] = "HALLAZGOS (codigo ${rc})"
        unstable("${nombre}: se detectaron hallazgos de seguridad (codigo ${rc})")
    }
    return rc
}

@NonCPS
def estadoComoTexto() {
    return ESTADO.collect { k, v -> "${k}=${v}" }.join('\n')
}

def generarTrazabilidad() {
    writeFile file: 'reports/pipeline-estado.txt', text: estadoComoTexto()
    run "docker run --rm -v \"${env.WORKSPACE}:/src\" -w /src " +
        "-e BUILD_NUMBER -e JOB_NAME -e BUILD_URL -e GIT_COMMIT -e GIT_BRANCH -e APP_IMAGE -e APP_IMAGE_ID " +
        "-e APP_VERSION=${env.VERSION_APP} -e ZAP_SCAN=${params.ZAP_SCAN} -e BUILD_RESULT=${currentBuild.currentResult} " +
        "${env.PY_IMAGE} python scripts/generar_trazabilidad.py"
}

// Pipeline
pipeline {
    agent any

    parameters {
        choice(name: 'APP_VERSION', choices: ['corregida', 'vulnerable'],
               description: 'Versión del código a construir y analizar')
        choice(name: 'ZAP_SCAN', choices: ['full', 'baseline'],
               description: 'full = escaneo activo (ataca el parámetro name). baseline = solo pasivo (rápido)')
        booleanParam(name: 'RUN_SONARQUBE', defaultValue: true,
                     description: 'Análisis con SonarQube (requiere el servidor levantado y la credencial sonar-token)')
        booleanParam(name: 'RUN_DEPENDENCY_CHECK', defaultValue: true,
                     description: 'Análisis de dependencias con OWASP Dependency-Check')
        booleanParam(name: 'SIMULAR_ATAQUE', defaultValue: false,
                     description: 'Genera tráfico malicioso controlado para probar la monitorización')
        string(name: 'SOURCE_DIR', defaultValue: '',
               description: 'Solo si NO usas Git: carpeta local del proyecto (ej. C:\\parcial3-devsecops)')
    }

    triggers { cron('H 6 * * 1') }

    options {
        skipDefaultCheckout()
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
    }

    environment {
        IMAGE_NAME      = 'parcial3-app'
        COMPOSE_PROJECT = 'parcial3'
        DOCKER_NET      = 'devsecops-net'
        SONAR_NET       = 'sonar-net'
        APP_URL         = 'http://app:5000/hello?name=TEST'
        PY_IMAGE        = 'python:3.12-slim'
        CURL_IMAGE      = 'curlimages/curl:8.11.0'
        ZAP_IMAGE       = 'ghcr.io/zaproxy/zaproxy:stable'
        SONAR_SCANNER   = 'sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1'
        DC_IMAGE        = 'owasp/dependency-check:13.0.0'
        NVD_DATAFEED    = 'https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/'
    }

    stages {
        stage('Checkout') {
            steps {
                script {
                    if (params.SOURCE_DIR?.trim()) {
                        echo "Copiando el código desde ${params.SOURCE_DIR}"
                        if (isUnix()) { sh "cp -a \"${params.SOURCE_DIR}/.\" ." }
                        else { bat "xcopy \"${params.SOURCE_DIR}\" \"%WORKSPACE%\" /E /I /Y /Q" }
                        env.GIT_COMMIT = 'N/A (copia local)'
                    } else {
                        def scmVars = checkout scm
                        env.GIT_COMMIT = scmVars.GIT_COMMIT ?: 'desconocido'
                        env.GIT_BRANCH = scmVars.GIT_BRANCH ?: ''
                    }
                    env.VERSION_APP = (env.BRANCH_NAME ?: '').contains('app_vulnerable') ? 'vulnerable' : params.APP_VERSION
                    if (env.BRANCH_NAME) { echo "Rama: ${env.BRANCH_NAME}" }
                    env.APP_DIR = env.VERSION_APP == 'vulnerable' ? 'app_vulnerable' : 'app'
                    env.APP_IMAGE = "${env.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    if (isUnix()) { sh 'rm -rf reports && mkdir -p reports && chmod 777 reports' }
                    else { bat 'if exist reports rmdir /s /q reports & mkdir reports' }
                    echo "Versión: ${env.VERSION_APP} (${env.APP_DIR}) | Commit: ${env.GIT_COMMIT}"
                    ESTADO['Checkout'] = 'OK'
                }
            }
        }

        stage('Build') {
            steps {
                script {
                    run "docker version"
                    run "docker build --target prod -f ${env.APP_DIR}/Dockerfile " +
                        "-t ${env.APP_IMAGE} -t ${env.IMAGE_NAME}:latest " +
                        "--label securedev.build=${env.BUILD_NUMBER} " +
                        "--label securedev.version=${env.VERSION_APP} " +
                        "--label \"securedev.commit=${env.GIT_COMMIT}\" ."
                    run "docker build --target test -f ${env.APP_DIR}/Dockerfile -t ${env.IMAGE_NAME}-test:${env.BUILD_NUMBER} ."
                    env.APP_IMAGE_ID = runOut("docker image inspect --format \"{{.Id}}\" ${env.APP_IMAGE}")
                    echo "Imagen construida: ${env.APP_IMAGE} (${env.APP_IMAGE_ID})"
                    ESTADO['Build'] = 'OK'
                }
            }
        }

        stage('Test') {
            steps {
                script {
                    control('Pruebas unitarias y de seguridad (pytest)',
                        "docker run --rm -v \"${ruta('reports')}:/reports\" ${env.IMAGE_NAME}-test:${env.BUILD_NUMBER}")
                }
            }
        }

        stage('Analyze: SAST (Bandit)') {
            steps {
                script {
                    def src = "/src/${env.APP_DIR}"
                    control('SAST Bandit',
                        "docker run --rm -v \"${env.WORKSPACE}:/src\" ${env.PY_IMAGE} sh -c \"" +
                        "pip install -q --root-user-action=ignore bandit==1.8.0 && " +
                        "bandit -q -r ${src} -f json -o /src/reports/bandit.json --exit-zero && " +
                        "bandit -q -r ${src} -f html -o /src/reports/bandit.html --exit-zero && " +
                        "bandit -r ${src} -ll\"")
                }
            }
        }

        stage('Analyze: SonarQube') {
            when { expression { return params.RUN_SONARQUBE } }
            steps {
                script {
                    try {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            int rc = runStatus("docker run --rm --network ${env.SONAR_NET} -v \"${env.WORKSPACE}:/usr/src\" " +
                                "-e SONAR_HOST_URL=http://sonarqube:9000 -e SONAR_TOKEN ${env.SONAR_SCANNER} " +
                                "-Dsonar.sources=${env.APP_DIR} -Dsonar.projectVersion=${env.VERSION_APP}-${env.BUILD_NUMBER}")
                            if (rc != 0) {
                                ESTADO['SAST SonarQube'] = "NO EJECUTADO (scanner codigo ${rc})"
                                echo "SonarQube no se pudo ejecutar (¿servidor apagado?). Se continúa sin bloquear."
                            } else {
                                int r = runStatus("docker run --rm --network ${env.SONAR_NET} -v \"${env.WORKSPACE}:/src\" -w /src " +
                                    "-e SONAR_TOKEN ${env.PY_IMAGE} python scripts/sonar_resumen.py http://sonarqube:9000 securedev")
                                if (r == 1) {
                                    ESTADO['SAST SonarQube'] = 'HALLAZGOS (codigo 1)'
                                    unstable('SonarQube: hallazgos de seguridad o Quality Gate fallido')
                                } else {
                                    ESTADO['SAST SonarQube'] = r == 0 ? 'OK' : "NO EJECUTADO (codigo ${r})"
                                }
                            }
                        }
                    } catch (e) {
                        ESTADO['SAST SonarQube'] = 'NO EJECUTADO (falta credencial sonar-token)'
                        echo "SonarQube omitido: ${e.message}"
                    }
                }
            }
        }

        stage('Security Test: Dependencias (pip-audit)') {
            steps {
                script {
                    def pa = "pip-audit -r /src/${env.APP_DIR}/requirements.txt --no-deps --disable-pip --progress-spinner off"
                    control('SCA pip-audit',
                        "docker run --rm -v \"${env.WORKSPACE}:/src\" ${env.PY_IMAGE} sh -c \"" +
                        "pip install -q --root-user-action=ignore pip-audit==2.7.3 && " +
                        "${pa} -f json -o /src/reports/pip-audit.json; " +
                        "${pa} -f cyclonedx-json -o /src/reports/sbom-cyclonedx.json; " +
                        "${pa} -f markdown --desc on -o /src/reports/pip-audit.md; " +
                        "${pa} --desc off\"")
                    runStatus("docker run --rm ${env.APP_IMAGE} pip list --outdated --disable-pip-version-check " +
                              "> \"${ruta('reports/dependencias-desactualizadas.txt')}\"")
                }
            }
        }

        stage('Security Test: OWASP Dependency-Check') {
            when { expression { return params.RUN_DEPENDENCY_CHECK } }
            steps {
                script {
                    def vol = "securedev-deps-${env.BUILD_NUMBER}"
                    def purelib = runOut("docker run --rm ${env.APP_IMAGE} python -c \"import sysconfig;print(sysconfig.get_paths()['purelib'])\"")
                    runStatus("docker volume rm ${vol}")
                    run "docker run --rm -v ${vol}:${purelib} ${env.APP_IMAGE} true"
                    control('SCA OWASP Dependency-Check',
                        "docker run --rm -v ${vol}:/deps:ro -v \"${env.WORKSPACE}:/src\" " +
                        "-v dependency-check-data:/usr/share/dependency-check/data " +
                        "${env.DC_IMAGE} --scan /deps --project securedev " +
                        "--enableExperimental --disableOssIndex --nvdDatafeed ${env.NVD_DATAFEED} " +
                        "--format HTML --format JSON --out /src/reports --failOnCVSS 7")
                    runStatus("docker volume rm ${vol}")
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    if (currentBuild.currentResult == 'UNSTABLE') {
                        if (env.VERSION_APP == 'corregida') {
                            ESTADO['Security Gate'] = 'BLOQUEADO'
                            error('Security Gate: hay hallazgos en la versión corregida. Se bloquea el despliegue.')
                        }
                        ESTADO['Security Gate'] = 'EXCEPCION LAB (version vulnerable)'
                        echo 'Versión vulnerable: se continúa SOLO para ejecutar el DAST en el laboratorio.'
                    } else {
                        ESTADO['Security Gate'] = 'APROBADO'
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'grafana-admin-password', variable: 'GRAFANA_PASSWORD')]) {
                        run "docker compose -p ${env.COMPOSE_PROJECT} up -d --remove-orphans"
                    }
                    runStatus("docker kill -s HUP securedev-prometheus")
                    run "docker run --rm --network ${env.DOCKER_NET} ${env.CURL_IMAGE} -sf --retry 15 " +
                        "--retry-connrefused --retry-delay 2 -o /dev/null \"${env.APP_URL}\""
                    ESTADO['Deploy'] = 'OK'
                }
            }
        }

        stage('Security Test: DAST (OWASP ZAP)') {
            steps {
                script {
                    def zapScript = params.ZAP_SCAN == 'full' ? 'zap-full-scan.py -m 2' : 'zap-baseline.py'
                    int rc = runStatus("docker run --rm --network ${env.DOCKER_NET} " +
                        "-v \"${ruta('reports')}:/zap/wrk:rw\" ${env.ZAP_IMAGE} ${zapScript} " +
                        "-t \"${env.APP_URL}\" -r zap-report.html -J zap-report.json -w zap-report.md -I")
                    if (rc != 0) {
                        unstable("OWASP ZAP terminó con código ${rc}")
                    }
                    control('DAST OWASP ZAP',
                        "docker run --rm -v \"${env.WORKSPACE}:/src\" -w /src ${env.PY_IMAGE} " +
                        "python scripts/evaluar_zap.py reports/zap-report.json")
                }
            }
        }

        stage('Simulación de incidente') {
            when { expression { return params.SIMULAR_ATAQUE } }
            steps {
                script {
                    run "docker run --rm --network ${env.DOCKER_NET} -v \"${env.WORKSPACE}:/src\" -w /src " +
                        "${env.PY_IMAGE} python scripts/simular_ataque.py http://app:5000 50"
                    echo 'Esperando a que Prometheus evalúe las reglas de alerta...'
                    sleep(time: 20, unit: 'SECONDS')
                    ESTADO['Simulacion de incidente'] = 'EJECUTADA'
                }
            }
        }

        stage('Monitor (Prometheus/Grafana)') {
            steps {
                script {
                    def curl = "docker run --rm --network ${env.DOCKER_NET} -v \"${ruta('reports')}:/reports\" " +
                               "${env.CURL_IMAGE} -sf --retry 5 --retry-connrefused -G http://prometheus:9090/api/v1/query"
                    run "${curl} --data-urlencode query=up -o /reports/monitor-targets.json"
                    run "${curl} --data-urlencode query=ALERTS -o /reports/monitor-alertas.json"
                    runStatus("docker logs --timestamps securedev-app > \"${ruta('reports/app-logs.txt')}\" 2>&1")
                    ESTADO['Monitorizacion'] = 'OK'
                    echo 'Grafana: http://localhost:3000  |  Prometheus: http://localhost:9090/alerts'
                }
            }
        }

        stage('Documentación y trazabilidad') {
            steps {
                script {
                    ESTADO['Documentacion'] = 'OK'
                    generarTrazabilidad()
                }
            }
        }
    }

    post {
        always {
            junit testResults: 'reports/junit.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            script {
                runStatus("docker image rm ${env.IMAGE_NAME}-test:${env.BUILD_NUMBER}")
            }
        }
        success {
            echo 'Pipeline OK: sin hallazgos de seguridad. Reportes en "Build Artifacts".'
        }
        unstable {
            echo 'Pipeline INESTABLE: hay hallazgos de seguridad. Revisar reports/TRAZABILIDAD.md.'
        }
        failure {
            script {
                try { generarTrazabilidad() } catch (e) { echo "No se pudo generar la trazabilidad: ${e}" }
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            echo 'Pipeline FALLIDO. Revisar la consola y reports/TRAZABILIDAD.md.'
        }
    }
}
