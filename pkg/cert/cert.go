package cert

type Cert struct {
	SecretName      string
	SecretNamespace string
	Expires         string
	Cert            string
	Key             string
}

func (*Cert) GetExpiration() {

}
