package main

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"password_gen/markov_chain"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()

type Response struct {
	Error    string `json:"error"`
	Password string `json:"password"`
}

type PasswordRestrictions struct {
	MinLength       int  `schema:"minLength"`
	MaxLength       int  `schema:"maxLength"`
	MinDigits       int  `schema:"minDigits"`
	MinSpecialChars int  `schema:"minSpecialChars"`
	MinLetters      int  `schema:"minLetters"`
	UserReadable    bool `schema:"userReadable"`
	AllUpperCase    bool `schemas:"allUpperCase"`
	AllLowerCase    bool `schemas:"allLowerCase"`
}

const (
	Letters      = "abcdefghijklmnopqrstuvwxyz"
	Digits       = "0123456789"
	SpecialChars = "~!@#$%^&*()_+-={}|[]:<>?,./"
)

func retryGeneratePassword(maxRetry int, restrictions PasswordRestrictions) (string, error) {
	var password string
	var err error
	for i := 0; i < maxRetry; i++ {
		password, err = generatePassword(restrictions)
		if err == nil {
			return password, nil
		}
	}
	return password, err
}

func generatePassword(restrictions PasswordRestrictions) (string, error) {
	var err error
	password := ""
	restrictedChars := ""

	password, err = generatePasswordBase(restrictions, password)
	if err != nil {
		return "", err
	}
	if restrictions.MinLength > 0 {
		password, err = padPasswordToLength(password, restrictions)
		if err != nil {
			return "", err
		}
	}
	if restrictions.MaxLength > 0 {
		password = slicePasswordToLength(password, restrictions)
	}

	if restrictions.MinSpecialChars > 0 {
		password, err = fillPasswordWithCharacterGroup(password, restrictions.MinSpecialChars, SpecialChars, restrictions.MaxLength, &restrictedChars)

		if err != nil {
			return "", err
		}
	}
	if restrictions.MinDigits > 0 {
		password, err = fillPasswordWithCharacterGroup(password, restrictions.MinDigits, Digits, restrictions.MaxLength, &restrictedChars)

		if err != nil {
			return "", err
		}
		restrictedChars += Digits
	}
	if restrictions.MinLetters > 0 {
		password, err = fillPasswordWithCharacterGroup(password, restrictions.MinLetters, Letters, restrictions.MaxLength, &restrictedChars)

		if err != nil {
			return "", err
		}
		restrictedChars += Letters
	}
	if restrictions.AllUpperCase {
		password = strings.ToUpper(password)
	}
	if restrictions.AllLowerCase {
		password = strings.ToLower(password)
	}
	return password, nil
}

func generatePasswordBase(restrictions PasswordRestrictions, prefix string) (string, error) {
	if restrictions.UserReadable {
		return generateUserReadablePassword(prefix)
	} else {
		return generateRandomPassword(restrictions.MaxLength)
	}
}

func generateUserReadablePassword(prefix string) (string, error) {
	return markov_chain.GetProbablePassword(prefix)
}

func generateRandomPassword(maxLength int) (string, error) {
	var password string

	for i := 0; i < maxLength; i++ {
		ch, err := randomElement(Letters + Digits + SpecialChars)
		if err != nil {
			return "", err
		}

		password, err = insertAtRandom(password, ch)
		if err != nil {
			return "", err
		}
	}

	return password, nil
}

func insertAtRandom(password string, value string) (string, error) {
	if password == "" {
		return value, nil
	}

	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(password))))
	if err != nil {
		return "", err
	}
	i := n.Int64()
	return password[0:i] + value + password[i:], nil
}

func randomElement(s string) (string, error) {
	reader := cryptorand.Reader
	n, err := cryptorand.Int(reader, big.NewInt(int64(len(s))))
	if err != nil {
		return "", err
	}
	return string(s[n.Int64()]), nil
}

func padPasswordToLength(password string, restrictions PasswordRestrictions) (string, error) {
	if len(password) < restrictions.MinLength {
		generatedPassword, err := generatePasswordBase(restrictions, password)
		if err != nil {
			return "", err
		}
		return padPasswordToLength(password+generatedPassword, restrictions)
	}
	return password, nil
}

func slicePasswordToLength(password string, restrictions PasswordRestrictions) string {
	diff := len(password) - restrictions.MaxLength
	skipFirst, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(2)))

	if diff > 0 {
		if skipFirst.Int64() > 0 {
			return password[diff:]
		}
		return password[:len(password)-diff]
	}
	return password
}

func fillPasswordWithCharacterGroup(password string, characterGroupRestriction int, characterGroup string, maxLength int, restrictedChars *string) (string, error) {
	charGroupRegexp, err := regexp.Compile(regexp.QuoteMeta(characterGroup))
	if err != nil {
		return "", errors.New("Something went wrong")
	}
	nonCharGroupRegexp, err := regexp.Compile("[^" + regexp.QuoteMeta(characterGroup+*restrictedChars) + "]")
	if err != nil {
		return "", errors.New("Something went wrong")
	}
	charGroupInPassword := len(charGroupRegexp.FindString(password))
	missingCharCount := characterGroupRestriction - charGroupInPassword

	for i := 0; i < missingCharCount; i++ {
		ch, err := randomElement(characterGroup)
		if err != nil {
			return "", err
		}
		replaceIndexes := nonCharGroupRegexp.FindAllStringIndex(password, -1)
		if replaceIndexes != nil {
			randomIndex, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(replaceIndexes))))
			if err != nil {
				return "", errors.New("Something went wrong while generating password, t1ry again")
			}
			*restrictedChars += ch
			replaceIndex := replaceIndexes[randomIndex.Int64()]
			password = password[:replaceIndex[0]] + ch + password[replaceIndex[0]+1:]
		} else {
			if maxLength > len(password) {
				*restrictedChars += ch
				password += ch
			} else {
				return password, errors.New("Something went wrong while generating password, try again")
			}
		}
	}
	return password, nil
}

func parseRestrictions(query url.Values) (PasswordRestrictions, error) {
	var passwordRestrictions PasswordRestrictions

	err := decoder.Decode(&passwordRestrictions, query)
	if err != nil {
		return passwordRestrictions, err
	}

	if passwordRestrictions.MaxLength == 0 {
		passwordRestrictions.MaxLength = 16
	}
	if passwordRestrictions.MinDigits > 0 && passwordRestrictions.MinDigits > passwordRestrictions.MaxLength {
		return passwordRestrictions, errors.New("Parameter minDigits can't be larger than maxLength")
	}
	if passwordRestrictions.MinSpecialChars > 0 && passwordRestrictions.MinDigits > passwordRestrictions.MaxLength {
		return passwordRestrictions, errors.New("Parameter minSpecialChars can't be larger than maxLength")
	}
	if passwordRestrictions.MinDigits+passwordRestrictions.MinSpecialChars+passwordRestrictions.MinLetters > passwordRestrictions.MaxLength {
		return passwordRestrictions, errors.New("Sum of parameters minDigits, minLetters and minSpecialChars can't be larger than maxLength")
	}
	if passwordRestrictions.MaxLength > 0 && passwordRestrictions.MinLength > passwordRestrictions.MaxLength {
		return passwordRestrictions, errors.New("Parameter minLength can't be larger than maxLength")
	}
	return passwordRestrictions, nil
}

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(400)
	json.NewEncoder(w).Encode(Response{Error: err.Error(), Password: ""})
}

func handlePasswordGen(w http.ResponseWriter, r *http.Request) {
	password := ""
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	restrictions, err := parseRestrictions(r.URL.Query())

	if err != nil {
		handleError(w, err)
		return
	}

	password, err = retryGeneratePassword(5, restrictions)
	if err != nil {
		handleError(w, err)
		return
	}
	encoder.Encode(Response{Error: "", Password: password})
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)

	myRouter.HandleFunc("/password-gen", handlePasswordGen).Methods("GET")
	fmt.Println("Random password generator service listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", myRouter))
}

func main() {
	train := flag.Bool("train", false, "train from dataset")
	flag.Parse()
	if *train {
		err := markov_chain.GeneratePropablePasswordsModel()
		if err != nil {
			log.Fatal("Could not train data")
		}
	}
	decoder.IgnoreUnknownKeys(true)
	handleRequests()
}
