pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(
            logRotator(
                numToKeepStr: '10'
            )
        )
    }

    environment {
        IMAGE_NAME = 'soar-suricata'
        COMPOSE_PROJECT_NAME = 'soar-suricata'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Project Structure') {
            steps {
                sh '''
                    set -eu

                    echo "===== WORKSPACE ====="
                    pwd

                    echo "===== PROJECT FILES ====="
                    ls -la

                    required_files="
                    soar.py
                    ai_report.py
                    config.py
                    decision.py
                    enrichment.py
                    notifier.py
                    response.py
                    storage.py
                    wazuh_client.py
                    Dockerfile
                    docker-compose.yml
                    requirements.txt
                    "

                    for file in $required_files
                    do
                        if [ ! -f "$file" ]; then
                            echo "Missing required file: $file"
                            exit 1
                        fi
                    done
                '''
            }
        }

        stage('Python Syntax Check') {
            steps {
                sh '''
                    set -eu

                    python3 -m py_compile \
                        soar.py \
                        ai_report.py \
                        config.py \
                        decision.py \
                        enrichment.py \
                        notifier.py \
                        response.py \
                        storage.py \
                        wazuh_client.py
                '''
            }
        }

        stage('Security Checks') {
            steps {
                sh '''
                    set -eu

                    echo "Checking that secrets are not committed..."

                    if grep -RIn \
                        --exclude='Jenkinsfile' \
                        --exclude='*.backup*' \
                        -E \
                        'AIza[0-9A-Za-z_-]{20,}|GEMINI_API_KEY=.*[^"]$|WAZUH_INDEXER_PASS="[^"]+"' \
                        .;
                    then
                        echo "Possible hardcoded credential detected."
                        exit 1
                    fi

                    echo "Secret check completed."
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    set -eu

                    docker build \
                        --pull \
                        --tag ${IMAGE_NAME}:${BUILD_NUMBER} \
                        --tag ${IMAGE_NAME}:latest \
                        .
                '''
            }
        }

        stage('Container Import Test') {
            steps {
                sh '''
                    set -eu

                    docker run \
                        --rm \
                        --entrypoint python3 \
                        ${IMAGE_NAME}:${BUILD_NUMBER} \
                        -c "
import ai_report
import config
import decision
import enrichment
import notifier
import response
import storage
import wazuh_client
print('Container module import test passed')
"
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    set -eu

                    test -r /etc/soar-lite.env

                    SOAR_IMAGE_TAG=${BUILD_NUMBER} \
                    docker compose \
                        up \
                        --detach \
                        --no-build \
                        --force-recreate
                '''
            }
        }

        stage('Verify Deployment') {
            steps {
                sh '''
                    set -eu

                    sleep 8

                    docker compose ps

                    running=$(
                        docker inspect \
                            --format='{{.State.Running}}' \
                            soar-suricata
                    )

                    if [ "$running" != "true" ]; then
                        echo "SOAR container is not running."
                        docker logs \
                            --tail 100 \
                            soar-suricata
                        exit 1
                    fi

                    echo "===== SOAR LOGS ====="

                    docker logs \
                        --tail 50 \
                        soar-suricata
                '''
            }
        }
    }

    post {
        success {
            echo 'SOAR Docker deployment succeeded.'
        }

        failure {
            echo 'SOAR deployment failed.'

            sh '''
                docker compose ps || true
                docker logs \
                    --tail 100 \
                    soar-suricata || true
            '''
        }

        always {
            cleanWs(
                deleteDirs: true,
                notFailBuild: true
            )
        }
    }
}
