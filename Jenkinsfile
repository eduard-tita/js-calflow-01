pipeline {
  agent any

  options {
    buildDiscarder logRotator(
        artifactDaysToKeepStr: '',
        artifactNumToKeepStr: '',
        daysToKeepStr: '1',
        numToKeepStr: '5'
    )
  }

  stages {
    stage('Build Javascript') {
      steps {
        sh 'npm install'
      }
    }

    stage('Policy') {
      steps {
        script {
          echo "env.NODE_EXECUTABLE: ${env.NODE_EXECUTABLE}"

          nexusPolicyEvaluation(
              enableDebugLogging: false,
              iqStage: 'build',
              iqApplication: 'js-calflow-01',
              failBuildOnNetworkError: true,
              iqScanPatterns: [
                  [scanPattern: 'package-lock.json']
              ],
              reachability: [
                  resultFile: 'reachability-result.json',
                  jsAnalysis: [
                      enable: true,
                      sourceFiles: [
                          [pattern: 'index.js']
                      ]
                  ]
              ]
          )

          archiveArtifacts(
              artifacts: '**/reachability-result.json',
              followSymlinks: false
          )
        }
      }
    }
  }
}
