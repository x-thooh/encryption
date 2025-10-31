package standard

type IGenerate interface {
	Generate() (string, string, error)
}
