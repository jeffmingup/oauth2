package models

//User 
type User struct {
	ID     string
	Detail string
}

func (u *User) GetID() string {
	return u.ID
}

func (u *User) GetDetail() string {
	return u.Detail
}
