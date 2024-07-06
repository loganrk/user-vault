package types

type User struct {
	Id       int    `gorm:"primarykey;size:16"`
	Username string `gorm:"username"`
	Password string `gorm:"password"`
	Name     string `gorm:"name"`
	State    int    `gorm:"state"`
	Status   int    `gorm:"status"`
}
