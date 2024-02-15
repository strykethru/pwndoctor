package pwndoc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func DownloadImagesInContent(findingPOC string, token string, client *http.Client, audit string) error {
	re1, _ := regexp.Compile(`src=\"(\d.*?)\"`)
	re2, _ := regexp.Compile(`\w{24}`)

	firstString := re1.FindAllString(findingPOC, -1)
	for foundString := range firstString {
		imageID := re2.FindAllString(firstString[foundString], -1)
		imagesURL := fmt.Sprintf("%s/api/images/%s", URL, imageID[0])
		var pwnDocImages APIResponseImage
		body, err := BodyFromGetRequest(imagesURL, token, client)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &pwnDocImages)
		if err != nil {
			return err
		}

		firstPartOfImage := strings.Split(pwnDocImages.Data.Value, ",")
		imageType := firstPartOfImage[0]
		var imageB64String string
		var imageFileExt string
		switch imageType {
		case "data:image/jpeg;base64":
			imageB64String = strings.ReplaceAll(pwnDocImages.Data.Value, "data:image/jpeg;base64,", "")
			imageFileExt = "jpeg"
		case "data:image/png;base64":
			imageB64String = strings.ReplaceAll(pwnDocImages.Data.Value, "data:image/png;base64,", "")
			imageFileExt = "png"
		}
		// add defaults
		decImage, err := base64.StdEncoding.DecodeString(imageB64String)
		if err != nil {
			log.Println(imageB64String)
			return err
		}
		imageFileName := fmt.Sprintf("exports/%s/images/%s.%s", audit, pwnDocImages.Data.ID, imageFileExt)
		err = os.WriteFile(imageFileName, decImage, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
