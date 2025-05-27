import ballerina/crypto as c;
import ballerina/random;

public function aesEcbAsImport() returns error? {
    string dataString = "Hello Ballerina!";
    byte[] data = dataString.toBytes();
    byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    foreach int i in 0 ... 15 {
        key[i] = <byte>(check random:createIntInRange(0, 255));
    }
    byte[] _ = check c:encryptAesEcb(data, key);
}
