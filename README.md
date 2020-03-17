## Install
eckey by java, support sm2/k1

## Usage

```java
    // newKey, default sm2, new ECKey(ECKey.KeyType.K1) for k1
    ECKey sm2key = new ECKey();
    System.out.println(sm2key.GetPrivate());
    System.out.println(sm2key.GetPublic());

    String message = "Hello World!";
    // use sha256 to hash the message
    String sigStr = sm2key.sign(message);
    System.out.println(sigStr);

    // verify the sigStr is signed by key 
    try {
        sm2key.verifyMessage(message, sigStr);
    } catch (SignatureException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }

    // recover the publicKey by sigStr and message 
    try {
        String recoverKey = ECKey.signedMessageToKey(message, sigStr);
        System.out.println(recoverKey);
    } catch (SignatureException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }

```

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.