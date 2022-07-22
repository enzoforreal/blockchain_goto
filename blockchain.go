package main

import(

      "crypto/sha256"
      "encoding/json"
      "fmt"
      "strconv"
      "time"


)

type Block struct {

data         map[string]interface{}
hash         string
previousHash string
timestamp    time.Time
pow          int    

}


type Blockchain struct {

genesisBlock Block 
chain        []Block
difficulty   int

}



func (b Block) calculateHash() string{

  data, _ := json.Marshal(b.data)
  blockData := b.previousHash +string(data) + b.timestamp.String() + strconv.Itoa(b.pow)
  blockHash := sha256.Sum256([]byte(blockData))


  return fmt.Sprintf("%x",blockHash)

}


