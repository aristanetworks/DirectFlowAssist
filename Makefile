#!/usr/bin/make
# Note: indent with tabs not spaces (make is very picky!)
###############################################################################
# Makefile for DirectFlow Assist for Firewalls
###############################################################################
# variable section
NAME = "DirectFlow Assist for Firewalls"

BUILD_ROOT_DIR = builds
#REPO_COMMON_DIR = ../common
REPO_BASE_DIR = .
BUILD_TOOLS_DIR = tools

SITE_PKG_SRC = $(REPO_BASE_DIR)/directflow_assist
PERSIST_COMMON = $(REPO_BASE_DIR)/persist_common
PERSIST_PAN = $(REPO_BASE_DIR)/persist_pan
PERSIST_FNET = $(REPO_BASE_DIR)/persist_fnet
PERSIST_CHKP = $(REPO_BASE_DIR)/persist_chkp
PERSIST_CYPH = $(REPO_BASE_DIR)/persist_cyphort
PERSIST_VARMOUR = $(REPO_BASE_DIR)/persist_varmour

BUILD_DIR_PAN = $(BUILD_ROOT_DIR)/directflow_assist_pan
PKG_DIR_PAN = $(BUILD_DIR_PAN)
BUILD_DIR_PAN_DEMO = $(BUILD_ROOT_DIR)/directflow_assist_pan_demo
PKG_DIR_PAN_DEMO = $(BUILD_DIR_PAN_DEMO)/directflow_assist

BUILD_DIR_FNET = $(BUILD_ROOT_DIR)/directflow_assist_fnet
PKG_DIR_FNET = $(BUILD_DIR_FNET)
BUILD_DIR_FNET_DEMO = $(BUILD_ROOT_DIR)/directflow_assist_fnet_demo
PKG_DIR_FNET_DEMO = $(BUILD_DIR_FNET_DEMO)/directflow_assist

BUILD_DIR_CHKP = $(BUILD_ROOT_DIR)/directflow_assist_chkp
PKG_DIR_CHKP = $(BUILD_DIR_CHKP)/
BUILD_DIR_CHKP_DEMO = $(BUILD_ROOT_DIR)/directflow_assist_chkp_demo
PKG_DIR_CHKP_DEMO = $(BUILD_DIR_CHKP_DEMO)/directflow_assist_chkp_demo

BUILD_DIR_CYPH = $(BUILD_ROOT_DIR)/directflow_assist_cyphort
PKG_DIR_CYPH = $(BUILD_DIR_CYPH)/

BUILD_DIR_VARMOUR = $(BUILD_ROOT_DIR)/directflow_assist_varmour
PKG_DIR_VARMOUR = $(BUILD_DIR_VARMOUR)/

###############################################################################

all: status pep8 pylint_errors_only test clean rpm
#all: status pep8 pylint_errors_only test clean inc_version sdist rpm

status:
	@echo "--------------------------------------------------------"
	@echo "Checking git branch, working directory and index status"
	@echo "--------------------------------------------------------"
	git status
	#@read -n1 -p "Press <ctrl-C> to abort, any key to continue..." key
	#@echo "\n"

pep8: 
	@echo "---------------------------------------------"
	@echo "Running pep8"
	@echo "---------------------------------------------"
	@PYTHONPATH=$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_PAN):$(PERSIST_FNET):$(PERSIST_CHKP):$(PERSIST_CYPH):$(PERSIST_VARMOUR); \
	find $(SITE_PKG_SRC) -name \*.py | xargs pep8 --statistics  --ignore E501
	@echo ""

pylint_errors_only: 
	@echo "---------------------------------------------"
	@echo "Running pylint --errors-only for PAN"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_PAN); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "CheckPoint|Fortigate|Cyphort|Varmour" | xargs pylint --errors-only --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint --errors-only for FNET"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_FNET); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "CheckPoint|PAN|Cyphort|Varmour" | xargs pylint --errors-only --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint --errors-only for CHKP"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_CHKP); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|Cyphort|Varmour" | xargs pylint --errors-only --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint --errors-only for CYPH"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_CYPH); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|CheckPoint|Varmour" | xargs pylint --errors-only --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint --errors-only for VARMOUR"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_VARMOUR); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|CheckPoint|Cyphort" | xargs pylint --errors-only --max-line-length=90
	@echo ""

# run with -i flag to continue for all packages, e.g. 'make -i pylint'
pylint: 
	@echo "---------------------------------------------"
	@echo "Running pylint for PAN"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_PAN); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "CheckPoint|Fortigate|Cyphort|Varmour" | xargs pylint --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint for FNET"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_FNET); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "CheckPoint|PAN|Cyphort|Varmour" | xargs pylint --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint for CHKP"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_CHKP); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|Cyphort|Varmour" | xargs pylint --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint for CYPH"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_CYPH); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|CheckPoint|Varmour" | xargs pylint --max-line-length=90
	@echo "---------------------------------------------"
	@echo "Running pylint for VARMOUR"
	@echo "---------------------------------------------"
	@PYTHONPATH=$$PYTHONPATH:$(SITE_PKG_SRC):$(PERSIST_COMMON):$(PERSIST_VARMOUR); \
	find $(SITE_PKG_SRC) -name \*.py | egrep -v "Fortigate|PAN|CheckPoint|Cyphort" | xargs pylint --max-line-length=90
	@echo ""

# for more output from unittest add '-b' option
test:
	@echo "---------------------------------------------"
	@echo "Running unit tests on: DFA pkg & PAN"
	@echo "---------------------------------------------"
	@PYTHONPATH=$(PERSIST_COMMON):$(PERSIST_PAN):$$PYTHONPATH; \
	python -m unittest discover tests/unit -v
	@echo "---------------------------------------------"
	@echo "Running unit tests on: CHKP"
	@echo "---------------------------------------------"
	@PYTHONPATH=$(PERSIST_COMMON):$(PERSIST_CHKP):$$PYTHONPATH; \
	python -m unittest discover tests/unit/chkp -v
	@echo "---------------------------------------------"
	@echo "Running unit tests on: FNET"
	@echo "---------------------------------------------"
	@PYTHONPATH=$(PERSIST_COMMON):$(PERSIST_FNET):$$PYTHONPATH; \
	python -m unittest discover tests/unit/fnet -v

	@echo "---------------------------------------------"
	@echo "Running unit tests on: VARMOUR"
	@echo "---------------------------------------------"
	@PYTHONPATH=$(PERSIST_COMMON):$(PERSIST_VARMOUR):$$PYTHONPATH; \
	python -m unittest discover tests/unit/varmour -v

	#@read -n1 -p "Press <ctrl-C> to abort, any key to continue..." key
	#@echo "\n"

clean:
	@echo "---------------------------------------------"
	@echo "Removing old build directories, *.pyc, *.pyo"
	@echo "---------------------------------------------"
	rm -rf $(BUILD_DIR_PAN)
	rm -rf $(BUILD_DIR_PAN_DEMO)
	rm -rf $(BUILD_DIR_FNET)
	rm -rf $(BUILD_DIR_FNET_DEMO)
	rm -rf $(BUILD_DIR_CHKP)
	rm -rf $(BUILD_DIR_CHKP_DEMO)
	rm -rf $(BUILD_DIR_CYPH)
	rm -rf $(BUILD_DIR_VARMOUR)
	find . -type f -regex ".*\.py[co]$$" -delete
	@echo ""

inc_version:
	@echo "---------------------------------------------"
	@echo "Auto increment build number"
	@echo "---------------------------------------------"
	python $(BUILD_TOOLS_DIR)/build_utils.py inc directflow_assist/__init__.py
	@echo ""

sdist: clean
	@echo "---------------------------------------------"
	@echo "Creating new build directories"
	@echo "---------------------------------------------"

	mkdir -p $(PKG_DIR_PAN)
	mkdir -p $(PKG_DIR_FNET)
	mkdir -p $(PKG_DIR_CHKP)
	mkdir -p $(PKG_DIR_CYPH)
	mkdir -p $(PKG_DIR_VARMOUR)

	@echo ""
	@echo "---------------------------------------------"
	@echo "Copying source files to build directories"
	@echo "---------------------------------------------"
	cp -r directflow_assist $(PKG_DIR_PAN)
	rm $(PKG_DIR_PAN)/directflow_assist/FortigateSyslogMsg.py
	rm $(PKG_DIR_PAN)/directflow_assist/CheckPointSyslogMsg.py
	rm $(PKG_DIR_PAN)/directflow_assist/CyphortSyslogMsg.py

	cp -r directflow_assist $(PKG_DIR_FNET)
	rm $(PKG_DIR_FNET)/directflow_assist/PANSyslogMsg.py
	rm $(PKG_DIR_FNET)/directflow_assist/CheckPointSyslogMsg.py
	rm $(PKG_DIR_FNET)/directflow_assist/CyphortSyslogMsg.py

	cp -r directflow_assist $(PKG_DIR_CHKP)
	rm $(PKG_DIR_CHKP)/directflow_assist/PANSyslogMsg.py
	rm $(PKG_DIR_CHKP)/directflow_assist/FortigateSyslogMsg.py
	rm $(PKG_DIR_CHKP)/directflow_assist/CyphortSyslogMsg.py

	cp -r directflow_assist $(PKG_DIR_CYPH)
	rm $(PKG_DIR_CYPH)/directflow_assist/PANSyslogMsg.py
	rm $(PKG_DIR_CYPH)/directflow_assist/FortigateSyslogMsg.py
	rm $(PKG_DIR_CYPH)/directflow_assist/CheckPointSyslogMsg.py

	cp -r directflow_assist $(PKG_DIR_VARMOUR)
	rm $(PKG_DIR_VARMOUR)/directflow_assist/PANSyslogMsg.py
	rm $(PKG_DIR_VARMOUR)/directflow_assist/FortigateSyslogMsg.py
	rm $(PKG_DIR_VARMOUR)/directflow_assist/CheckPointSyslogMsg.py
	rm $(PKG_DIR_VARMOUR)/directflow_assist/CyphortSyslogMsg.py

	#cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_PAN)/common
	#cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_FNET)/common
	#cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_CHKP)/common
	#cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_CYPH)/common

	cp persist_common/* $(BUILD_DIR_PAN)
	cp persist_common/* $(BUILD_DIR_FNET)
	cp persist_common/* $(BUILD_DIR_CHKP)
	cp persist_common/* $(BUILD_DIR_CYPH)
	cp persist_common/* $(BUILD_DIR_VARMOUR)

	cp persist_pan/* $(BUILD_DIR_PAN)
	cp persist_fnet/* $(BUILD_DIR_FNET)
	cp persist_chkp/* $(BUILD_DIR_CHKP)
	cp persist_cyphort/* $(BUILD_DIR_CYPH)
	cp persist_varmour/* $(BUILD_DIR_VARMOUR)

	@echo ""
	@echo "---------------------------------------------"
	@echo "Building DFA PAN source distribution package"
	@echo "---------------------------------------------"
	cd $(BUILD_DIR_PAN) && python2.7 setup.py sdist 

	@echo ""
	@echo "---------------------------------------------"
	@echo "Building DFA FNET source distribution package"
	@echo "---------------------------------------------"
	cd $(BUILD_DIR_FNET) && python2.7 setup.py sdist 

	@echo ""
	@echo "---------------------------------------------"
	@echo "Building DFA CHKP source distribution package"
	@echo "---------------------------------------------"
	cd $(BUILD_DIR_CHKP) && python2.7 setup.py sdist 

	@echo ""
	@echo "---------------------------------------------"
	@echo "Building DFA CYPH source distribution package"
	@echo "---------------------------------------------"
	cd $(BUILD_DIR_CYPH) && python2.7 setup.py sdist 
	@echo ""

	@echo ""
	@echo "---------------------------------------------"
	@echo "Building DFA VARMOUR source distribution package"
	@echo "---------------------------------------------"
	cd $(BUILD_DIR_VARMOUR) && python2.7 setup.py sdist
	@echo ""

demo:
	@echo "---------------------------------------------"
	@echo "Creating new demo build directories"
	@echo "---------------------------------------------"
	mkdir -p $(PKG_DIR_PAN_DEMO)/common
	mkdir -p $(PKG_DIR_FNET_DEMO)/common
	@echo ""
	@echo "---------------------------------------------"
	@echo "Copying source files to demo build directories"
	@echo "---------------------------------------------"
	cp directflow_assist/*.py $(PKG_DIR_PAN_DEMO)
	rm $(PKG_DIR_PAN_DEMO)/FortigateSyslogMsg.py
	cp directflow_assist/*.py $(PKG_DIR_FNET_DEMO)
	rm $(PKG_DIR_FNET_DEMO)/PANSyslogMsg.py
	cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_PAN_DEMO)/common
	cp $(REPO_COMMON_DIR)/*.py $(PKG_DIR_FNET_DEMO)/common
	cp demo_pkg/site_pkg_adds/* $(PKG_DIR_PAN_DEMO)
	cp demo_pkg/site_pkg_adds/* $(PKG_DIR_FNET_DEMO)
	cp persist_common/* $(BUILD_DIR_PAN_DEMO)
	cp persist_common/* $(BUILD_DIR_FNET_DEMO)
	cp persist_pan/README.txt $(BUILD_DIR_PAN_DEMO)
	cp persist_fnet/README.txt $(BUILD_DIR_FNET_DEMO)
	cp demo_pkg/persist_dfa_pan_demo/*  $(BUILD_DIR_PAN_DEMO)
	cp demo_pkg/persist_dfa_fnet_demo/*  $(BUILD_DIR_FNET_DEMO)
	@echo ""
	@echo "--------------------------------------------------"
	@echo "Building DFA PAN DEMO source distribution package"
	@echo "--------------------------------------------------"
	cd $(BUILD_DIR_PAN_DEMO) && python2.7 setup.py sdist 
	@echo ""
	#@echo "---------------------------------------------------"
	#@echo "Building DFA FNET DEMO source distribution package"
	#@echo "---------------------------------------------------"
	#cd $(BUILD_DIR_FNET_DEMO) && python2.7 setup.py sdist 
	#@echo ""
	

rpm: clean sdist
# rpm: clean inc_version sdist
	@echo ""
	@echo "--------------------------------------------------"
	@echo "untaring the file created by sdist"
	@echo "--------------------------------------------------"

	tar zxf $(REPO_BASE_DIR)/builds/directflow_assist_pan/dist/directflow_assist_pan*
	cd directflow_assist_pan* && export HOME=$(REPO_BASE_DIR)/ && python setup.py bdist_rpm 

	tar zxf $(REPO_BASE_DIR)/builds/directflow_assist_fnet/dist/directflow_assist_fnet*
	cd directflow_assist_fnet* && export HOME=$(REPO_BASE_DIR)/ && python setup.py bdist_rpm 

	tar zxf $(REPO_BASE_DIR)/builds/directflow_assist_chkp/dist/directflow_assist_chkp*
	cd directflow_assist_chkp* && export HOME=$(REPO_BASE_DIR)/ && python setup.py bdist_rpm 

	tar zxf $(REPO_BASE_DIR)/builds/directflow_assist_cyphort/dist/directflow_assist_cyphort*
	cd directflow_assist_cyphort* && export HOME=$(REPO_BASE_DIR)/ && python setup.py bdist_rpm 

	tar zxf $(REPO_BASE_DIR)/builds/directflow_assist_varmour/dist/directflow_assist_varmour*
	cd directflow_assist_varmour* && export HOME=$(REPO_BASE_DIR)/ && python setup.py bdist_rpm 
