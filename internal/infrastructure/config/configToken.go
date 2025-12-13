package config

type Jwt interface {
	GetMethod() string
	GetHmacKey() string
	GetRsaPrivateKeyPath() string
	GetRsaPublicKeyPath() string
}

func (t tokenJWT) GetMethod() string {
	return t.Method
}

func (t tokenJWT) GetHmacKey() string {
	return t.HmacKey
}

func (t tokenJWT) GetRsaPrivateKeyPath() string {
	return t.RsaPrivateKeyPath
}

func (t tokenJWT) GetRsaPublicKeyPath() string {
	return t.RsaPublicKeyPath
}
