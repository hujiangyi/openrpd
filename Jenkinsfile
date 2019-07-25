#!groovy

def RPD_DIR = "openrpd"
def RPD_UT_DIR = "openrpd-ut"
COMMIT_TITLE = "default message"
def WRT_DIR = "openwrt"
//def RPD_BRANCH = "master"
//def RPD_REFSPEC = "refs/heads/master"
def RPD_CONFIG = 'build/x86/x86.config'
def CORE_CONFIG = 'build/x86/core-sim.config'
String RPD_VM_LABEL = "${env.BUILD_NUMBER}_rpd"
String CORE_VM_LABEL = "${env.BUILD_NUMBER}_core"
def DL_CACHE_DIR = '~/dl'


def configureNode(DIR) {
    sh "sudo ${DIR}/.jenkinsfile/configure_node.sh"
}

def getVersion(DIR) {
    echo "getVersion(DIR=${DIR})"

    def VERSION = sh(returnStdout: true, script: "${DIR}/.jenkinsfile/create_version_info.sh openrpd ${DIR} /tmp/openrpd_image_info | head -1").trim()
    echo "VERSION = ${VERSION}"
    return VERSION
}

def build(feedSrcDir, configFile, fileSuffix, debug, DIR) {
    echo "build(feedSrcDir=${feedSrcDir}, configFile=${configFile}, fileSuffix=${fileSuffix}, debug=${debug}, DIR=${DIR})"

    getVersion(DIR)

    def PWD = sh(returnStdout: true, script: 'pwd').trim()
    echo "pwd = ${PWD}"
    sh "${DIR}/.jenkinsfile/configure_build.sh ${feedSrcDir} ${configFile} ${fileSuffix} ${debug}"
    def NUM_PROCS = sh(returnStdout: true, script: 'grep -c ^processor /proc/cpuinfo').trim()
    try {
        if (DEBUG_BUILD == "true") {
            echo "DEBUG BUILD set to ${DEBUG_BUILD}, performing slow, verbose build intentionally..."
            sh "export RPD_IMAGE_INFO_F=/tmp/openrpd_image_info && make -j1 V=s"
        } else {
            sh "export RPD_IMAGE_INFO_F=/tmp/openrpd_image_info && make -j${NUM_PROCS}"
        }
    } catch (e) {
        echo "Warning: ${e}"
        try {
            retry(5) {
                sh 'rm -Rf /tmp/pip_build_*'
                sh "export RPD_IMAGE_INFO_F=/tmp/openrpd_image_info && make -j1 V=s"
                currentBuild.result = 'SUCCESS'
            }
        } catch (e1) {
            echo "Warning: ${e1}"
            currentBuild.result = 'FAILURE'
            slackSend color: 'danger', message: "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build FAILURE: ${COMMIT_TITLE}"
            error 'Build failed'
        }
    }
    sh "mv ./bin/x86/openwrt-x86-generic-combined-ext4.vmdk ./bin/x86/openwrt-x86-generic-combined-ext4_${fileSuffix}.vmdk"
}


def buildPython(DIR) {
    sh "${DIR}/.jenkinsfile/build_python.sh"
}


def runUnitTests(DIR) {
    echo "Attempting unit test, aborting in 30 minutes if stuck...."
    timeout(time: 30, unit: 'MINUTES') {
        sh "${DIR}/.jenkinsfile/run_unit_tests.sh"
    }
}

def checkoutSource(RPD_DIR, WRT_DIR) {

    // OPENWRT_KEYWORD is a substring of the OpenWRT build job on Jenkins
    def OPENWRT_KEYWORD = "openwrt"

    checkoutRefspec = { uri, refspec ->
        try {
            sh "git fetch ${uri} ${refspec} && git checkout FETCH_HEAD"
            String COMMIT_TITLE = sh(returnStdout: true, script: 'git log -1 --pretty=%s').trim()
            echo "COMMIT_TITLE = ${COMMIT_TITLE}"
        } catch (MissingPropertyException mpe) {
            echo "No refspec provided, building from master HEAD: ${mpe}"
        }
    }

    parallel(
            checkoutRpd: {
                dir(RPD_DIR) {
                    //git credentialsId: '4c865548-54c4-4ac4-bb58-6b126ee96bff', url: 'ssh://gerrit.cablelabs.com:29418/openrpd'
                    sh "git clone ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openrpd ."
                    if (!"${env.JOB_NAME}".contains(OPENWRT_KEYWORD)) {
                        checkoutRefspec("ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openrpd", "${GERRIT_REFSPEC}")
                    } else {
                        checkoutRefspec("ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openrpd", "${OPENRPD_REFSPEC}")
                    }
                }
            },
            checkoutWrt: {
                dir(WRT_DIR) {
                    //git branch: 'chaos_calmer_openrpd', credentialsId: '4c865548-54c4-4ac4-bb58-6b126ee96bff', url: 'ssh://gerrit.cablelabs.com:29418/openwrt'
                    sh "git clone -b chaos_calmer_openrpd ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openwrt ."
                    if ("${env.JOB_NAME}".contains(OPENWRT_KEYWORD)) {
                        checkoutRefspec("ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openwrt", "${GERRIT_REFSPEC}")
                    }
                }
            }
    )
}


node('openrpd-ut') {

    stage('configure test') {

        def RELEASE_DESCRIPTION = sh(returnStdout: true, script: 'lsb_release -s -d').trim()
        if (RELEASE_DESCRIPTION != "Ubuntu 14.04.4 LTS" &&
                RELEASE_DESCRIPTION != "Ubuntu 14.04.5 LTS") {
            error "Sorry, only Ubuntu 14.04.4 or .5 LTS is supported at this time. Your version: ${RELEASE_DESCRIPTION}"
        }

        // clean the current workspace
        deleteDir()

        checkoutSource(RPD_UT_DIR, WRT_DIR)

        configureNode(RPD_UT_DIR)

        // install flake8 for PEP8 report generation and generate warnings report
        sh "pip install flake8"
        sh "flake8 --config=${RPD_UT_DIR}/.flake8 --exit-zero ${RPD_UT_DIR}/openrpd/rpd/ ${RPD_UT_DIR}/openrpd/rpd_service_suite/ > flake8.log"
        warnings canComputeNew: false, canResolveRelativePaths: false, defaultEncoding: '', excludePattern: '', healthy: '1000', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'Pep8', pattern: 'flake8.log']], unHealthy: '2500'

        dir(RPD_UT_DIR) {

            def WORKSPACE = pwd()

            buildPython("./")

            sh '''#!/bin/bash
source /tmp/openrpd/venv/bin/activate

echo "## Make the project"
cd openrpd
make
'''

        }
    }

    dir(RPD_UT_DIR) {

        def WORKSPACE = pwd()

        stage('make doc') {
            sh '''#!/bin/bash
source /tmp/openrpd/venv/bin/activate

echo "## Make documentation"
cd openrpd
export SPHINX_APIDOC_OPTIONS='members,special-members,private-members,undoc-members,show-inheritance'
cd ../docs/
rm -Rf source/
sphinx-apidoc -o ./source/ ../openrpd/
sphinx-build ./ ./_build/html/
'''

            publishHTML([allowMissing: false, alwaysLinkToLastBuild: false, keepAll: false, reportDir: 'docs/_build/html/', reportFiles: 'index.html', reportName: 'OpenRPD Documentation', reportTitles: ''])
            archiveArtifacts "docs/_build/html/**"
        }

        stage('unit test') {
            env.PYTHONPATH = "${WORKSPACE}/openrpd/:${WORKSPACE}/openrpd/rpd/l2tp"
            try {
                retry(2) {
                    runUnitTests("./")
                }
            } catch (e) {
                echo "Warning: ${e}"
                echo "Rebuilding python venv..."
                sh 'rm /tmp/openrpd/python-venv-complete'
                buildPython("./")
                try {
                    retry(2) {
                        runUnitTests("./")
                    }
                } catch (e1) {
                    echo "Warning: ${e1}"
                    currentBuild.result = 'FAILURE'
                    slackSend color: 'danger', message: "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build FAILURE: ${COMMIT_TITLE}"
                    error 'Unit test failed'
                }
            }

            step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'openrpd/coverage.xml', failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])

            archiveArtifacts "openrpd/coverage.xml"
        }

    }
}


node('openrpd-build') {

//	slackSend "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build started"

    def WORKSPACE = pwd()

    stage('configure build') {

        def RELEASE_DESCRIPTION = sh(returnStdout: true, script: 'lsb_release -s -d').trim()
        if (RELEASE_DESCRIPTION != "Ubuntu 14.04.4 LTS" &&
                RELEASE_DESCRIPTION != "Ubuntu 14.04.5 LTS") {
            error "Sorry, only Ubuntu 14.04.4 or .5 LTS is supported at this time. Your version: ${RELEASE_DESCRIPTION}"
        }

        // clean the current workspace
        deleteDir()

        checkoutSource(RPD_DIR, WRT_DIR)

    }

    String feedSrcDir = "${WORKSPACE}/${RPD_DIR}"
    stage('build rpd') {
        dir(WRT_DIR) {
            try {
                sh "if [ ! -d dl ]; then mkdir dl; fi"
                sh "cp ${DL_CACHE_DIR}/* ./dl/"
            } catch (e) {
                echo "Info: ${e}"
            }
            RPD_VM_LABEL = getVersion(feedSrcDir) + "_rpd"
            build(feedSrcDir, RPD_CONFIG, RPD_VM_LABEL, DEBUG_BUILD, feedSrcDir)
        }
    }

    stage('build core') {
        dir(WRT_DIR) {
            sh 'find . -name odhcp6c-2015-07-13|xargs rm -rf'
            CORE_VM_LABEL = getVersion(feedSrcDir) + "_core"
            build(feedSrcDir, CORE_CONFIG, CORE_VM_LABEL, DEBUG_BUILD, feedSrcDir)
        }
    }

    stash name: 'vmdks', includes: "${WRT_DIR}/bin/x86/*.vmdk"

    dir(WRT_DIR) {
        sh "if [ ! -d ${DL_CACHE_DIR} ]; then mkdir ${DL_CACHE_DIR}; fi"
        sh "cp ./dl/* ${DL_CACHE_DIR}/"
    }
}

node('openrpd-it') {

    def WORKSPACE = pwd()

    deleteDir()

    checkoutSource(RPD_DIR, WRT_DIR)

    unstash 'vmdks'

    stage('integration test') {
        sh 'kvm-ok'
        env.PYTHONPATH = "${WORKSPACE}/${RPD_DIR}/openrpd/"
        try {
            dir(env.PYTHONPATH) {
                sh 'make'
//				TODO: add try/catch (slackSend) here when re-enabling
                timeout(time: 20, unit: 'MINUTES') {
                    sh "python -m rpd_service_suite.its_basic --force-cleanup"
                    sh "python -m rpd_service_suite.its_basic --rpd-image=\"${WORKSPACE}/${WRT_DIR}/bin/x86/openwrt-x86-generic-combined-ext4_${RPD_VM_LABEL}.vmdk\" --server-image=\"${WORKSPACE}/${WRT_DIR}/bin/x86/openwrt-x86-generic-combined-ext4_${CORE_VM_LABEL}.vmdk\""
                }
            }
        }
        finally {
            archiveArtifacts "${RPD_DIR}/openrpd/IT/**"
            archiveArtifacts "${WRT_DIR}/bin/x86/*.vmdk"
        }
    }

    slackSend color: "good", message: "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build SUCCESS: ${COMMIT_TITLE}"
}

