package mapper

import (
	v1 "github.com/RyseUp/uniqora-nft-marketplace/api/user/v1"
	"github.com/RyseUp/uniqora-nft-marketplace/internal/models"
)

func ModelToProtoUserInfo(user *models.User) *v1.User {
	return &v1.User{
		UserName:  user.UserName,
		Email:     user.Email,
		AvatarUrl: user.AvatarURL,
	}
}
