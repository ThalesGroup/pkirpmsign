#!/bin/bash

TEST_OK_COUNT=0
TEST_KO_COUNT=0
TEST_SKIPPED_COUNT=0
TEST_TOTAL_COUNT=0
START_TIME=$(date +%s%N | cut -b1-13)

WORKING_DIR="/var/tmp"
TEST_CASES_LIST_PATH="${WORKING_DIR}/test_cases.txt"
CURRENT_TEST_DIR="${WORKING_DIR}/current_test"
DEFAULT_SIGN_FILES_DIR="${WORKING_DIR}/default_files_sign"
DEFAULT_VERIFY_FILES_DIR="${WORKING_DIR}/default_files_verify"
RPM_VERIFY_TRUSTED_CERTS_DIR="/etc/pki/rpm-certs"

PROPERTIES_FILE_NAME="testconfig.properties"
EXPECTED_TERMINAL_FILE_NAME="expected.txt"
EXPECTED_TERMINAL_ERROR_FILE_NAME="expected_error.txt"
ACTUAL_TERMINAL_FILE_NAME="actual.txt"
ACTUAL_TERMINAL_ERROR_FILE_NAME="actual_error.txt"
EXPECTED_FILE_NAME="expected.rpm"
INPUT_RPM_FILE_NAME="test.rpm"
P12_DEFAULT_FILE_NAME="keystore.p12"
CERTS_DEFAULT_DIR_NAME="rpm-certs"

SIGN_COMMAND="${CURRENT_TEST_DIR}/pkirpmsign"
VERIFY_COMMAND="${CURRENT_TEST_DIR}/pkirpmverify"

EXPECTED_TERMINAL_OUTPUT_PATH="${CURRENT_TEST_DIR}/${EXPECTED_TERMINAL_FILE_NAME}"
EXPECTED_TERMINAL_ERROR_OUTPUT_PATH="${CURRENT_TEST_DIR}/${EXPECTED_TERMINAL_ERROR_FILE_NAME}"
ACTUAL_TERMINAL_OUTPUT_PATH="${CURRENT_TEST_DIR}/${ACTUAL_TERMINAL_FILE_NAME}"
ACTUAL_TERMINAL_ERROR_OUTPUT_PATH="${CURRENT_TEST_DIR}/${ACTUAL_TERMINAL_ERROR_FILE_NAME}"

# ------------------------------------------------------- #
# === BEGINING OF DEFAULT VALUE FOR FIELDS ===
# Following fields are all default values for fields that can be declared in testconfig.properties for each test
# In some cases the field must be declared in testconfig.properties, in this case the default value is NODEFAULT

### SHARED CONFIG
TEST_TYPE_DEFAULT="NODEFAULT"
INPUT_RPM_PATH_DEFAULT="${CURRENT_TEST_DIR}/${INPUT_RPM_FILE_NAME}"
COMMAND_ARGS_DEFAULT="${INPUT_RPM_PATH_DEFAULT}"
USE_DEFAULT_FILES_IF_NON_EXISTING_DEFAULT="true"

### SIGNATURE CONFIG

EXPECTED_RPM_OUTPUT_PATH_DEFAULT="${CURRENT_TEST_DIR}/${EXPECTED_FILE_NAME}"
P12_FILE_DIR_DEFAULT="/etc/pki/rpm-keys"
DEFAULT_P12_DIRECTORY_EXISTS_DEFAULT="true"
P12_PASSWORD_DEFAULT="password"
VERIFY_RPM_CONTENT_AFTER_SIGNATURE_DEFAULT="true"
DEFAULT_P12_FILE_EXISTS_DEFAULT="true"
RPM_LEFT_UNSIGNED_DEFAULT="false"

### VERIFICATION CONFIG

VERIFICATION_PEM_FILES_PATHS_DEFAULT="NODEFAULT"
DEFAULT_VERIFICATION_CERTIFICATE_DIRECTORY_EXISTS_DEFAULT="true"
DEFAULT_CERT_FILES_EXISTS_DEFAULT="true"
CERTS_DIR_DEFAULT="/etc/pki/rpm-certs"
# === END OF DEFAULT VALUE FOR FIELDS ===
# ------------------------------------------------------- #
# === BEGINING OF ACTUAL VALUE FOR FIELDS ===
# Following values are reset for each test. To set default values for them see previous section (a default value must be
# stored in a field named '<ACTUAL_FIELD_NAME>_DEFAULT')
#
# Each variable is explained in tests/properties.txt

### SHARED CONFIG ###
# The name of the test, it must be the name of the folder in which test is declared. This folder must be in tests/ directory
# format is NN_NNN_description_of_the_test
# This directory must at least contain a testconfig.properties with mandatory fields declared
TEST_NAME=""
TEST_TYPE=""

INPUT_RPM_PATH=""
INPUT_RPM_DIR=""
COMMAND_ARGS=""
USE_DEFAULT_FILES_IF_NON_EXISTING=""

### SIGNATURE CONFIG ONLY ###
EXPECTED_RPM_OUTPUT_PATH=""
EXPECTED_RPM_OUTPUT_DIR=""
P12_FILE_DIR=""
DEFAULT_P12_DIRECTORY_EXISTS=""
P12_PASSWORD=""
VERIFY_RPM_CONTENT_AFTER_SIGNATURE=""
DEFAULT_P12_FILE_EXISTS=""
RPM_LEFT_UNSIGNED=""

### VERIFICATION CONFIG ONLY ###
VERIFICATION_PEM_FILES_PATHS=""
DEFAULT_VERIFICATION_CERTIFICATE_DIRECTORY_EXISTS=""
DEFAULT_CERT_FILES_EXISTS=""
CERTS_DIR=""

# === END OF ACTUAL VALUE FOR FIELDS ===
# ------------------------------------------------------- #
COMMAND_EXECUTED=""

retrieve_config_parameter() {
	if [[ -z $1 ]]; then
    	echo "ERROR : retrieving properties from file requires one argument : the name of the property."
    	exit 1;
    fi
	grep -w "^${1}" ${CURRENT_TEST_DIR}/${PROPERTIES_FILE_NAME} | cut -d '=' -f 2- | tr -d '\n'
}

set_individual_parameter() {
	varname="$1";
	varnamedefaultvalue="${varname}_DEFAULT"
	retrievevaluecommand="${varname}"'=$tmp'
	defaultvaluecommand="${varname}=\$$varnamedefaultvalue"
	tmp=$(retrieve_config_parameter "${varname}") && [[ ! -z "$tmp" ]] && eval $retrievevaluecommand || eval $defaultvaluecommand
}

set_parameters() {
	if [[ -z $1 ]]; then
    	echo "ERROR : setting parameters requires one argument : the name of the test."
    	exit 1;
    fi
	### SHARED CONFIG
	TEST_NAME="${1}"
	set_individual_parameter TEST_TYPE

	set_individual_parameter INPUT_RPM_PATH
	INPUT_RPM_DIR=$(dirname ${INPUT_RPM_PATH})
	set_individual_parameter COMMAND_ARGS
	set_individual_parameter USE_DEFAULT_FILES_IF_NON_EXISTING

	### SIGNATURE CONFIG
	set_individual_parameter EXPECTED_RPM_OUTPUT_PATH
	EXPECTED_RPM_OUTPUT_DIR=$(dirname ${EXPECTED_RPM_OUTPUT_PATH})
	set_individual_parameter P12_FILE_DIR
	set_individual_parameter DEFAULT_P12_DIRECTORY_EXISTS
	set_individual_parameter P12_PASSWORD
	set_individual_parameter VERIFY_RPM_CONTENT_AFTER_SIGNATURE
	set_individual_parameter DEFAULT_P12_FILE_EXISTS
	set_individual_parameter RPM_LEFT_UNSIGNED

	### VERIFICATION CONFIG
	set_individual_parameter VERIFICATION_PEM_FILES_PATHS
	set_individual_parameter DEFAULT_VERIFICATION_CERTIFICATE_DIRECTORY_EXISTS
	set_individual_parameter DEFAULT_CERT_FILES_EXISTS
	set_individual_parameter CERTS_DIR
}

prepare_files_signature() {

	# Create input rpm
	cp "${WORKING_DIR}/${TEST_NAME}/${INPUT_RPM_FILE_NAME}" "${INPUT_RPM_DIR}" 2>/dev/null
	# Create expected rpm
	if [ "$RPM_LEFT_UNSIGNED" = "true" ]; then
		cp "${WORKING_DIR}/${TEST_NAME}/${INPUT_RPM_FILE_NAME}" "${EXPECTED_RPM_OUTPUT_DIR}/${EXPECTED_FILE_NAME}" 2>/dev/null
	else
		cp "${WORKING_DIR}/${TEST_NAME}/${EXPECTED_FILE_NAME}" "${EXPECTED_RPM_OUTPUT_DIR}" 2>/dev/null
	fi
	# Create expected stdout file
	cp "${WORKING_DIR}/${TEST_NAME}/${EXPECTED_TERMINAL_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
	# Create expected stderr file
	cp "${WORKING_DIR}/${TEST_NAME}/${EXPECTED_TERMINAL_ERROR_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null

	# Create p12 file
	if [ "$DEFAULT_P12_DIRECTORY_EXISTS" = "true" ]; then
		mkdir -p "$P12_FILE_DIR"
		if [ "$DEFAULT_P12_FILE_EXISTS" = "true" ]; then
			cp "${WORKING_DIR}/${TEST_NAME}/${P12_DEFAULT_FILE_NAME}" "${P12_FILE_DIR}" 2>/dev/null
		fi
	fi

	# For each previous element : if it does not exist then use the default value
	# (unless config specifies it should not be done)
	if [ "$USE_DEFAULT_FILES_IF_NON_EXISTING" = "true" ]; then

		if [[ ! -f "${INPUT_RPM_PATH}" ]]; then
			cp "${DEFAULT_SIGN_FILES_DIR}/${INPUT_RPM_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi

		if [[ ! -f "${EXPECTED_RPM_OUTPUT_PATH}" ]]; then
			if [ "$RPM_LEFT_UNSIGNED" = "true" ]; then
				cp "${DEFAULT_SIGN_FILES_DIR}/${INPUT_RPM_FILE_NAME}" "${CURRENT_TEST_DIR}/${EXPECTED_FILE_NAME}" 2>/dev/null
			else
				cp "${DEFAULT_SIGN_FILES_DIR}/${EXPECTED_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
			fi
		fi

		if [[ ! -f "${EXPECTED_TERMINAL_OUTPUT_PATH}" ]]; then
			cp "${DEFAULT_SIGN_FILES_DIR}/${EXPECTED_TERMINAL_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi
		if [[ ! -f "${EXPECTED_TERMINAL_ERROR_OUTPUT_PATH}" ]]; then
			cp "${DEFAULT_SIGN_FILES_DIR}/${EXPECTED_TERMINAL_ERROR_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi

		if [ "$DEFAULT_P12_DIRECTORY_EXISTS" = "true" ] && [ "$DEFAULT_P12_FILE_EXISTS" = "true" ]; then
			if [[ ! -f "${P12_FILE_DIR}/${P12_DEFAULT_FILE_NAME}" ]]; then
				cp "${DEFAULT_SIGN_FILES_DIR}/${P12_DEFAULT_FILE_NAME}" "${P12_FILE_DIR}" 2>/dev/null
			fi
		fi

	fi

}

prepare_files_verification() {

	mkdir "${CERTS_DIR}"

	# Create input rpm
	cp "${WORKING_DIR}/${TEST_NAME}/${INPUT_RPM_FILE_NAME}" "${INPUT_RPM_DIR}" 2>/dev/null

	# Create expected stdout file
	cp "${WORKING_DIR}/${TEST_NAME}/${EXPECTED_TERMINAL_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
	# Create expected stderr file
	cp "${WORKING_DIR}/${TEST_NAME}/${EXPECTED_TERMINAL_ERROR_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null

	# Create cert files
	if [ "$DEFAULT_VERIFICATION_CERTIFICATE_DIRECTORY_EXISTS" = "true" ]; then
		mkdir -p "$RPM_VERIFY_TRUSTED_CERTS_DIR"
		if [ "$DEFAULT_CERT_FILES_EXISTS" = "true" ]; then
			cp -r "${WORKING_DIR}/${TEST_NAME}/${CERTS_DEFAULT_DIR_NAME}" "${CERTS_DIR}/.." 2>/dev/null
		fi
	fi

	# For each previous element : if it does not exist then use the default value
	# (unless config specifies it should not be done)
	if [ "$USE_DEFAULT_FILES_IF_NON_EXISTING" = "true" ]; then

		if [[ ! -f "${INPUT_RPM_PATH}" ]]; then
			cp "${DEFAULT_VERIFY_FILES_DIR}/${INPUT_RPM_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi

		if [[ ! -f "${EXPECTED_TERMINAL_OUTPUT_PATH}" ]]; then
			cp "${DEFAULT_VERIFY_FILES_DIR}/${EXPECTED_TERMINAL_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi
		if [[ ! -f "${EXPECTED_TERMINAL_ERROR_OUTPUT_PATH}" ]]; then
			cp "${DEFAULT_VERIFY_FILES_DIR}/${EXPECTED_TERMINAL_ERROR_FILE_NAME}" "${CURRENT_TEST_DIR}" 2>/dev/null
		fi

		if [ "$DEFAULT_VERIFICATION_CERTIFICATE_DIRECTORY_EXISTS" = "true" ] && [ "$DEFAULT_CERT_FILES_EXISTS" = "true" ]; then
			if [[ -z "$(ls -A ${CERTS_DIR})" ]]; then
				cp -r "${DEFAULT_VERIFY_FILES_DIR}/${CERTS_DEFAULT_DIR_NAME}" "${CERTS_DIR}/.." 2>/dev/null
			fi
		fi

	fi

}

init_new_test() {
	if [[ -z $1 ]]; then
    	echo "ERROR : init new test requires one argument : the name of the test."
    	exit 1;
    fi
    testname=$1
	# Clean
	# Following commands clean all files in $CURRENT_TEST_DIR EXCEPT test_in_container.sh, pkirpmsign and pkirpmverify
	find $CURRENT_TEST_DIR -type f ! \( -name 'test_in_container.sh' -o -name 'pkirpmsign'  -o -name 'pkirpmverify' \) -delete
	# Don't delete $P12_FILE_DIR if it is parent of $CURRENT_TEST_DIR !
	if [[ ! "$CURRENT_TEST_DIR" == "$P12_FILE_DIR"*  ]]; then
		rm -rf $P12_FILE_DIR
	fi
	# Don't delete $CERTS_DIR if it is parent of $CURRENT_TEST_DIR !
	if [[ ! "$CURRENT_TEST_DIR" == "$CERTS_DIR"*  ]]; then
		rm -rf $CERTS_DIR
	fi
	rm -rf $P12_FILE_DIR_DEFAULT
	rm -rf $CERTS_DIR_DEFAULT
	# Set test properties file
	cp "${WORKING_DIR}/${testname}/${PROPERTIES_FILE_NAME}" ${CURRENT_TEST_DIR}
	# Reset command executed variable
	COMMAND_EXECUTED=""
}

run_sign_test() {

	COMMAND_EXECUTED="${SIGN_COMMAND} ${COMMAND_ARGS}"
	eval "$COMMAND_EXECUTED <<!
${P12_PASSWORD}
!" 2> "${ACTUAL_TERMINAL_ERROR_OUTPUT_PATH}" > "${ACTUAL_TERMINAL_OUTPUT_PATH}"

}

run_verify_test() {

	COMMAND_EXECUTED="${VERIFY_COMMAND} ${COMMAND_ARGS}"
	eval "$COMMAND_EXECUTED" 2> "${ACTUAL_TERMINAL_ERROR_OUTPUT_PATH}" > "${ACTUAL_TERMINAL_OUTPUT_PATH}"

}

successful_test() {
	((TEST_OK_COUNT++))
	echo -e "[\033[1;32mOK\033[0m] : test success ${TEST_NAME}"
}

unsuccessful_test() {
	((TEST_KO_COUNT++))
	echo -e "[\033[1;31mKO\033[0m] : test failure ${TEST_NAME}"
}

test_checks() {

	result="ok"
	msg=""

	if ! cmp --silent $EXPECTED_TERMINAL_OUTPUT_PATH $ACTUAL_TERMINAL_OUTPUT_PATH; then
		result="ko"
		msg="\033[1;31mWrong terminal output\033[0m for test ${TEST_NAME}.\n\t<<<expected>>>\n$(cat $EXPECTED_TERMINAL_OUTPUT_PATH)\n\t<<</expected>>>\n but got\n\t<<<actual>>>\n$(cat $ACTUAL_TERMINAL_OUTPUT_PATH)\n\t<<</actual>>>\n"
	fi

	if ! cmp --silent $EXPECTED_TERMINAL_ERROR_OUTPUT_PATH $ACTUAL_TERMINAL_ERROR_OUTPUT_PATH; then
		result="ko"
		msg="$msg\033[1;31mWrong terminal error output\033[0m for test ${TEST_NAME}.\n\t<<<expected>>>\n$(cat $EXPECTED_TERMINAL_ERROR_OUTPUT_PATH)\n\t<<</expected>>>\n but got\n\t<<<actual>>>\n$(cat $ACTUAL_TERMINAL_ERROR_OUTPUT_PATH)\n\t<<</actual>>>\n"
	fi

	# In case the test is a verify test there is no need to verify 'output' rpm since rpm is left intact
	if [[ "$TEST_TYPE" = "SIGN" ]]; then
		if [[ "${VERIFY_RPM_CONTENT_AFTER_SIGNATURE}" = "true" ]]; then
			if ! cmp --silent $EXPECTED_RPM_OUTPUT_PATH $INPUT_RPM_PATH; then
				result="ko"
				msg="$msg\033[1;31mWrong rpm output\033[0m for test ${TEST_NAME}. Output rpm is not as expected, run the test manually and read output rpm with tools like xxd for debugging\n"
			fi
		fi
	fi

	if [[ "$result" = "ok" ]]; then
		successful_test
	else
		echo -n -e "$msg"
		echo "Originated by the following command : $COMMAND_EXECUTED"
		unsuccessful_test
	fi

}

launch_test() {

	if [[ -z $1 ]]; then
    	echo "ERROR : launching test requires one argument : the name of the test."
    	exit 1;
    fi
    testname=$1

	init_new_test $testname

	set_parameters $testname

	case $TEST_TYPE in
		SIGN)
			prepare_files_signature
			run_sign_test
			;;
		VERIFY)
			prepare_files_verification
			run_verify_test
			;;
		*)
			echo "ERROR : Unknown test type : $TEST_TYPE"
			exit 1;
			;;
	esac

	test_checks

}

launch_all_tests() {
	echo -e "Test suite starting\n"
	IFS=$'\n'
	set -f
	for line in $(cat < "${TEST_CASES_LIST_PATH}"); do
		((TEST_TOTAL_COUNT++))
		if [[ -d "${WORKING_DIR}/${line}" ]]; then
			launch_test "${line}"
		else
			((TEST_SKIPPED_COUNT++))
			echo -e "[\033[1;33mWARNING\033[0m] : test '${line}' declared in '${TEST_CASES_LIST_PATH}' does not exist, skipping..."
		fi
	done
}

print_time() {
	TIME="$(($(date +%s%N | cut -b1-13) - ${START_TIME}))"
	TIME_WITHOUT_MS=${TIME::-3}
	if [ ! -z $TIME_WITHOUT_MS ]; then
		echo -n $(date -d "@$TIME_WITHOUT_MS" +'%Mm %Ss - ')
	fi
	echo "${TIME: -3}ms"
}

compute_percent() {
	echo "$((100 * ${1} / ${TEST_TOTAL_COUNT}))"
}

tests_report() {
	echo -e "\nTest suite ended\n"
	echo "==== Test report ===="
	echo -e "Elapsed time : $(print_time)\nTotal number of test declared : ${TEST_TOTAL_COUNT}\nTests successes : ${TEST_OK_COUNT}    Tests failures : ${TEST_KO_COUNT}    Tests skipped : ${TEST_SKIPPED_COUNT}"
	echo -e "Success : $(compute_percent ${TEST_OK_COUNT})%    Failure : $(compute_percent ${TEST_KO_COUNT})%    Skipped : $(compute_percent ${TEST_SKIPPED_COUNT})%\n"
}

launch_all_tests
tests_report
