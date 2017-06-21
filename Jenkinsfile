pipeline {
  agent any
  stages {
    stage('Test') {
      steps {
        parallel(
          "Test": {
            sh 'echo hi'
            echo 'hi'
            
          },
          "Test2": {
            sh 'echo hi'
            
          }
        )
      }
    }
  }
}