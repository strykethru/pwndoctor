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

func DownloadImagesInContent(findingPOC string, token string, client *http.Client, audit string) {
	re1, _ := regexp.Compile(`src=\"(\d.*?)\"`)
	re2, _ := regexp.Compile(`\w{24}`)

	firstString := re1.FindAllString(findingPOC, -1)
	for foundString := range firstString {
		imageID := re2.FindAllString(firstString[foundString], -1)
		imagesURL := fmt.Sprintf("%s/api/images/%s", URL, imageID[0])
		var pwnDocImages APIResponseImage
		body, err := BodyFromGetRequest(imagesURL, token, client)
		if err != nil {
			log.Fatal("Error reading response body (AUDIT INFO): ", err)
		}
		err = json.Unmarshal(body, &pwnDocImages)
		if err != nil {
			fmt.Println(body)
			log.Fatal("Error Unmarshalling (AUDIT INFO): ", err)
		}

		firstPartOfImage := strings.Split(pwnDocImages.Data.Value, ",")
		imageType := firstPartOfImage[0]
		var imageB64String string
		var imageFileName string
		switch imageType {
		case "data:image/jpeg;base64":
			imageB64String = strings.ReplaceAll(pwnDocImages.Data.Value, "data:image/jpeg;base64,", "")
			imageFileName = fmt.Sprintf("exports/%s/images/%s.jpeg", audit, pwnDocImages.Data.ID)
		case "data:image/png;base64":
			imageB64String = strings.ReplaceAll(pwnDocImages.Data.Value, "data:image/png;base64,", "")
			imageFileName = fmt.Sprintf("exports/%s/images/%s.png", audit, pwnDocImages.Data.ID)
		}
		// add defaults
		decImage, _ := base64.RawStdEncoding.DecodeString(imageB64String)
		_ = os.WriteFile(imageFileName, decImage, 0644)
	}
}
