#!groovy

def RPD_DIR = "openrpd"
def RPD_UT_DIR = "openrpd-ut"
COMMIT_TITLE = "default message"
def WRT_DIR = "openwrt"
def RPD_BRANCH = "master"
def RPD_REFSPEC = "refs/heads/master"
def RPD_CONFIG = 'build/x86/x86.config'
def CORE_CONFIG = 'build/x86/core-sim.config'
def RPD_VM_LABEL = 'rpd'
def CORE_VM_LABEL = 'core'
def DL_CACHE_DIR = '~/dl'
def APT_INSTALLS = [
	"bridge-utils",
	"build-essential",
	"daemontools",
	"gawk",
	"gettext",
	"git-core",
	"libffi-dev",
	"libncurses5-dev",
	"libssl-dev",
	"libvirt-bin",
	"mercurial",
	"protobuf-c-compiler",
	"protobuf-compiler",
	"psmisc",
	"pylint",
	"python-dev",
	"python-paramiko",
	"python-pip",
	"python-protobuf",
	"qemu-kvm",
	"redis-server",
	"sshpass",
	"subversion",
	"ubuntu-vm-builder",
	"unzip"
]


def configureNode(APT_INSTALLS) {
	sh 'sudo apt-get update'
	sh 'sudo apt-get upgrade -y'

	def packages = APT_INSTALLS.join(" ")
	echo "packages to install via apt: ${packages}"
	sh "sudo apt-get install -y ${packages}"
}


def build(feedSrcDir, configFile, fileSuffix, debug) {
	echo "build(feedSrcDir=${feedSrcDir}, configFile=${configFile}, fileSuffix=${fileSuffix}, debug=${debug})"

	sh "echo \"src-link openrpd ${feedSrcDir}\" > feeds.conf"
	sh 'scripts/feeds update -a'
	sh 'scripts/feeds install -a'
	sh "cp ${configFile} .config"
	sh 'echo "CONFIG_TARGET_x86=y" >> .config'
	sh 'echo "CONFIG_TARGET_x86_generic=y" >> .config'
	sh 'echo "CONFIG_TARGET_x86_generic_Generic=y" >> .config'
	sh 'make defconfig'
	def NUM_PROCS = sh(returnStdout: true, script: 'grep -c ^processor /proc/cpuinfo').trim()
	try {
		if (DEBUG_BUILD == "true") {
			echo "DEBUG BUILD set to ${DEBUG_BUILD}, performing slow, verbose build intentionally..."
			sh 'make -j1 V=s'
		} else {
			sh "make -j${NUM_PROCS}"
		}
	} catch (e) {
		echo "Warning: ${e}"
		try {
			retry(5) {
				sh 'rm -Rf /tmp/pip_build_*'
				sh 'make -j1 V=s'
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


def buildPython() {

	sh '''#!/bin/bash

TMPDIR=/tmp/openrpd

ps -A | grep syslog
if [[ $? != "0" ]]; then
	echo "### Starting rsyslog..."
	sudo service rsyslog start
fi

if [ ! -f /tmp/openrpd/python-venv-complete ]; then
	pip install virtualenv

	mkdir -p $TMPDIR

	cp package/lang/python/patches/012-l2tp-socket-support.patch $TMPDIR

	cd $TMPDIR
	wget https://www.python.org/ftp/python/2.7.9/Python-2.7.9.tar.xz
	tar xvJf Python-2.7.9.tar.xz
	cd $TMPDIR/Python-2.7.9/Modules
	patch -p2 <$TMPDIR/012-l2tp-socket-support.patch
	cd $TMPDIR/Python-2.7.9
	./configure --prefix=`pwd`
	make
	make install
	cd $TMPDIR
	virtualenv -p $TMPDIR/Python-2.7.9/bin/python venv

	source venv/bin/activate

	pip install fysom protobuf-to-dict glibc
	pip install pyzmq --install-option="--zmq=bundled"
	pip install sortedcontainers
	pip install python-daemon
	pip install protobuf
	pip install redis
	pip install coverage
	pip install flake8
	pip install scp
	pip install psutil
	pip install pyasn1
	pip install pyasn1-modules
	pip install pyopenssl
	pip install tftpy
	pip install urllib
	pip install ipaddress

	pip install sphinx

	touch /tmp/openrpd/python-venv-complete
fi
'''


}


def runUnitTests() {
	echo "Attempting unit test, aborting in 30 minutes if stuck...."
	timeout(time: 30, unit: 'MINUTES') {
		sh '''#!/bin/bash
RETCODE=0
source /tmp/openrpd/venv/bin/activate

## Run unit tests
cd openrpd
coverage run --rcfile=.coverage.rc rpd/rpd_unit_tests.py -v || RETCODE=1
coverage xml

exit $RETCODE
'''
	}
}

def checkoutSource(RPD_DIR, WRT_DIR) {

	// OPENWRT_KEYWORD is a substring of the OpenWRT build job on Jenkins
	def OPENWRT_KEYWORD = "openwrt"

	def checkoutRefspec = { uri ->
		try {
			sh "git fetch ${uri} ${GERRIT_REFSPEC} && git checkout FETCH_HEAD"
			COMMIT_TITLE = sh(returnStdout: true, script: 'git log -1 --pretty=%s').trim()
			echo "COMMIT_TITLE = ${COMMIT_TITLE}"
		} catch (MissingPropertyException mpe) {
			echo "No GERRIT_REFSPEC provided, building from master HEAD: ${mpe}"
		}
	}

	parallel(
		checkoutRpd: {
			dir(RPD_DIR) {
				git credentialsId: '4c865548-54c4-4ac4-bb58-6b126ee96bff', url: 'ssh://gerrit.cablelabs.com:29418/openrpd'
				if (!"${env.JOB_NAME}".contains(OPENWRT_KEYWORD)) {
					checkoutRefspec("ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openrpd")
				}
			}
		},
		checkoutWrt: {
			dir(WRT_DIR) {
				git branch: 'chaos_calmer_openrpd', credentialsId: '4c865548-54c4-4ac4-bb58-6b126ee96bff', url: 'ssh://gerrit.cablelabs.com:29418/openwrt'
				if ("${env.JOB_NAME}".contains(OPENWRT_KEYWORD)) {
					checkoutRefspec("ssh://c3jenkins_cl-lvslav01@gerrit.cablelabs.com:29418/openwrt")
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

		def packages = APT_INSTALLS.join(" ")
		echo "packages to install via apt: ${packages}"
		sh "sudo apt-get install -y ${packages}"

		sh "pip install flake8"
		sh "flake8 --config=${RPD_UT_DIR}/.flake8 --exit-zero ${RPD_UT_DIR}/openrpd/rpd/ ${RPD_UT_DIR}/openrpd/rpd_service_suite/ > flake8.log"
		warnings canComputeNew: false, canResolveRelativePaths: false, defaultEncoding: '', excludePattern: '', healthy: '1000', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'Pep8', pattern: 'flake8.log']], unHealthy: '2500'

		dir(RPD_UT_DIR) {

			def WORKSPACE = pwd()

			buildPython()
	
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
					runUnitTests()
				}
			} catch (e) {
				echo "Warning: ${e}"
				echo "Rebuilding python venv..."
				sh 'rm /tmp/openrpd/python-venv-complete'
				buildPython()
				try {
					retry(2) {
						runUnitTests()
					}
				} catch (e1) {
					echo "Warning: ${e1}"
                        		currentBuild.result = 'FAILURE'
                        		slackSend color: 'danger', message: "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build FAILURE: ${COMMIT_TITLE}"
                        		error 'Unit test failed'
				}
			}
					
			step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'openrpd/coverage.xml', failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
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

	def feedSrcDir = "${WORKSPACE}/${RPD_DIR}"
	stage('build rpd') {
		dir(WRT_DIR) {
			try {
				sh "if [ ! -d dl ]; then mkdir dl; fi"
				sh "cp ${DL_CACHE_DIR}/* ./dl/"
			} catch (e) {
				echo "Info: ${e}"
			}
			build(feedSrcDir, RPD_CONFIG, RPD_VM_LABEL, DEBUG_BUILD)
		}
	}

	stage('build core') {
		dir(WRT_DIR) {
			sh 'find . -name odhcp6c-2015-07-13|xargs rm -rf'
			build(feedSrcDir, CORE_CONFIG, CORE_VM_LABEL, DEBUG_BUILD)
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
		finally	{
			archiveArtifacts "${RPD_DIR}/openrpd/IT/**"
			archiveArtifacts "${WRT_DIR}/bin/x86/*.vmdk"
		}
	}

	slackSend color: "good", message: "${env.JOB_NAME} - <${env.BUILD_URL}|#${env.BUILD_NUMBER}> build SUCCESS: ${COMMIT_TITLE}"
}

