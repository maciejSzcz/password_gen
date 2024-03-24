package markov_chain

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/mb-14/gomarkov"
	"github.com/montanaflynn/stats"
)

type model struct {
	Mean   float64         `json:"mean"`
	StdDev float64         `json:"std_dev"`
	Chain  *gomarkov.Chain `json:"chain"`
}

const minimumProbability = 0.05

func getDataset(fileName string) []string {
	file, _ := os.Open(fileName)
	scanner := bufio.NewScanner(file)
	var list []string
	for scanner.Scan() {
		list = append(list, scanner.Text())
	}
	return list
}

func sequenceProbablity(chain *gomarkov.Chain, input string) float64 {
	tokens := strings.Split(input, "")
	logProb := float64(0)
	pairs := gomarkov.MakePairs(tokens, chain.Order)
	for _, pair := range pairs {
		prob, _ := chain.TransitionProbability(pair.NextState, pair.CurrentState)
		if prob > 0 {
			logProb += math.Log10(prob)
		} else {
			logProb += math.Log10(minimumProbability)
		}
	}
	return math.Pow(10, logProb/float64(len(pairs)))
}

func getScores(chain *gomarkov.Chain) []float64 {
	scores := make([]float64, 0)
	for _, data := range getDataset("./passwords.txt") {
		score := sequenceProbablity(chain, data)
		scores = append(scores, score)
	}
	return scores
}

func saveModel(model model) {
	jsonObj, _ := json.Marshal(model)
	err := os.WriteFile("./model.json", jsonObj, 0644)
	if err != nil {
		fmt.Println(err)
	}
}

func loadModel() (model, error) {
	data, err := os.ReadFile("./model.json")
	if err != nil {
		return model{}, err
	}
	var m model
	err = json.Unmarshal(data, &m)
	if err != nil {
		return model{}, err
	}
	return m, nil
}

func GetProbablePassword(prefix string) (string, error) {
	model, err := loadModel()
	if err != nil {
		return "", errors.New("User readable password can't be generated, try again later")
	}
	order := model.Chain.Order
	tokens := make([]string, 0)
	for i := 0; i < order; i++ {
		tokens = append(tokens, gomarkov.StartToken)
	}
	if prefix != "" {
		tokens = append(tokens, strings.Split(prefix, "")...)
	}
	for tokens[len(tokens)-1] != gomarkov.EndToken {
		next, err := model.Chain.Generate(tokens[(len(tokens) - order):])
		if err != nil {
			return "", errors.New("User readable password can't be generated, try again later")
		}
		tokens = append(tokens, next)
	}

	return strings.Join(tokens[order:len(tokens)-1], ""), nil
}

func GeneratePropablePasswordsModel() error {
	var model model
	var err error
	chain := gomarkov.NewChain(2)
	for _, data := range getDataset("./passwords.txt") {
		chain.Add(strings.Split(data, ""))
	}
	scores := getScores(chain)
	model.StdDev, err = stats.StandardDeviation(scores)
	if err != nil {
		return err
	}
	model.Mean, err = stats.Mean(scores)
	if err != nil {
		return err
	}
	model.Chain = chain

	saveModel(model)
	return nil
}
