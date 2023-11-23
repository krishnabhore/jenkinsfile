pipeline {
    agent any

    environment {
        HELM_CHART_NAME = 'bookapp'
        HELM_NAMESPACE = 'bookapp'
        ENV_FILE_PATH = '.env'
    }

    stages {
        stage('Docker Image') {
            steps {
                script {
                    // Load environment variables from the .env file
                    load(".env")

                    // Run Helm Upgrade
                    sh """
                        echo "HWLLOW"
                        echo \${MY_NAME}

                    """
                }
            }
        }
    }
}
