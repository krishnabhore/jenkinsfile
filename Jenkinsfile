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
                if( "${BUILD_BOOKS_IMAGE}" == "yes"){
                    sh """
                    date 
                    pwd
                    ll
                    """
                    
                }
                else{
                    echo "failed hai bhai"
                }    
                if("yes" == "yes"){
                    sh """
                    echo "sahi hai"
                    """
                    
                }                    
                }
            }
        }
    }
}
