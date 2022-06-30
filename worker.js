var fs = require("fs");
var util = require('util');
var dgram = require("dgram");
var crypto = require("crypto");
var stream = require('stream');
var Crypt = require("khawn2u-crypt");

var crypt = new Crypt();

var parseContract = function(U8array) {
    var data = U8array;
    var Signed = [];
    while (data[0]) {
        var signiture = crypt.BufferToSignedMessage(data);
        var Addr = crypt.secp256k1.toAdress(crypt.secp256k1.recoverPublicKey(signiture));
        Signed.push(Addr);
        data = signiture.Message;
    }
    data = data.subarray(1);
    var len = data[0]+1;
    var date = new Date(Number(crypt.bufferToBigInt(data.subarray(1,len))));
    data = data.subarray(len);
    var Terms = [];
    while (data.length) {
        var Addr = "0x"+crypt.bufferToBigInt(data.subarray(0,33)).toString(16);
        data = data.subarray(33);
        len = data[0]+1;
        var am = crypt.bufferToBigInt(data.subarray(1,len));
        if (am&1n) {
            am = -(am>>1n);
        } else {
            am >>= 1n;
        }
        data = data.subarray(len);
        len = data[0]+1;
        var st = Number(crypt.bufferToBigInt(data.subarray(1,len)));
        data = data.subarray(len);
        Terms.push({
            Adress: Addr,
            Payment: amountToString(am),
            Storage: st,
            Signed: Signed.includes(Addr),
        });
    }
    return {
        Date:date,
        Terms:Terms,
        arrayBuffer:U8array,
        Standard:"KC-131"
    }
}
var parseTx = function(buff) {
    var To = "0x"+crypt.bufferToBigInt(buff.subarray(0,33)).toString(16);
    var idx = 34;
    var len = buff[33];
    var Id = Number(crypt.bufferToBigInt(buff.subarray(idx,idx+len)));
    idx += len+1;
    len = buff[idx-1];
    var Am = crypt.bufferToBigInt(buff.subarray(idx,idx+len));
    idx += len+1;
    len = buff[idx-1];
    var Fe = crypt.bufferToBigInt(buff.subarray(idx,idx+len));
    idx += len+1;
    len = buff[idx-1];
    var Ch = crypt.bufferToBigInt(buff.subarray(idx,idx+len));
    return {
        arrayBuffer:buff,
        To:To,
        Fee:{RawTokenAmount:Fe,Value:Number(Fe)/1000000000000000000},
        Amount:{RawTokenAmount:Am,Value:Number(Am)/1000000000000000000},
        Change:{RawTokenAmount:Ch,Value:Number(Ch)/1000000000000000000},
        Nonce:Id,
        Standard:"KC-128"
    }
}
var parseSignedTx = function(buff) {
    var SignedTx = crypt.BufferToSignedMessage(buff);
    var Tx = parseTx(SignedTx.Message);
    Tx.From = crypt.secp256k1.toAdress(crypt.secp256k1.recoverPublicKey(SignedTx));
    Tx.arrayBuffer = buff;
    return Tx;
}
var parseEncryptedMessage = function(msgbfr) {
    var len = msgbfr[33]+34;
    return {
        arrayBuffer:msgbfr,
        Message: msgbfr.slice(len),
        Key: "0x"+crypt.bufferToBigInt(msgbfr.slice(34,len)).toString(16),
        To: "0x"+crypt.bufferToBigInt(msgbfr.slice(0,33)).toString(16),
        Standard:"KC-129"
    };
}
var AES256Enc = function(msg,key) {
    var cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key), null);
    return Buffer.concat([cipher.update(msg),cipher.final()]);
}
var AES256Dec = function(msg,key) {
    var cipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key), null);
    return Buffer.concat([cipher.update(msg),cipher.final()]);
}
var decryptMessage = function(msg,sk) {
    if (!sk) {
        sk = PrivateKey;
    }
    var key = crypt.secp256k1.decryptWithPrivateKey(msg.Key,sk);
    var dec = AES256Dec(msg.Message,key);
    console.log(dec);
    var signiture = crypt.BufferToSignedMessage(dec);
    msg.DecryptedMessage = signiture.Message.toString('utf-8');
    msg.From = crypt.secp256k1.toAdress(crypt.secp256k1.recoverPublicKey(signiture));
    return msg;
}
var parseAmount = function(a) {
    if (a.constructor === String) {
        var idx = a.indexOf(".");
        if (idx == -1) {
            return BigInt(a)*1000000000000000000n;
        } else {
            var result = BigInt(a.split(".").join(""));
            idx = a.length-idx-1;
            if (idx > 18) {
                return result/(10n**BigInt(idx-18));
            } else {
                return result*(10n**BigInt(18-idx));
            }
        }
    } else if (a.constructor === BigInt) {
        return a;
    } else if (a.constructor === Number) {
        return BigInt(a*1000000000000000000);
    }
}
var Zeros = "0".repeat(256);
var amountToString = function(am) {
    if (am >= 0) {
        return (am/1000000000000000000n).toString()+"."+(Zeros+(am%1000000000000000000n).toString()).slice(-18);
    } else {
        am = -am;
        return "-"+(am/1000000000000000000n).toString()+"."+(Zeros+(am%1000000000000000000n).toString()).slice(-18);
    }
}
var parseStorageSize = function(stsize) {
    if (stsize.endsWith("KB")) {
        return parseFloat(stsize)*1024;
    } else if (stsize.endsWith("MB")) {
        return parseFloat(stsize)*1048576;
    } else if (stsize.endsWith("GB")) {
        return parseFloat(stsize)*1073741824;
    } else if (stsize.endsWith("TB")) {
        return parseFloat(stsize)*1099511627776;
    } else {
        return parseInt(stsize);
    }
}
var AES256DecStream = function(strm,key) {
    var cipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key), null);
    strm.pipe(cipher);
    return cipher;
}
var AES256EncStream = function(strm,key) {
    var cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key), null);
    strm.pipe(cipher);
    return cipher;
}
var writeStream = function(dataStream,adress) {
    var Hash = new crypt.Hash.Keccak(256, [1, 256, 65536, 16777216], 256);
    dataStream.on('data',function(d){
        Hash.update(d);
    });
    var path = filePath+adress;
    if (!fs.existsSync(path)) {
        fs.mkdirSync(path);
    }
    var tmpID = crypt.toHex(crypt.randomBytes(32));
    path += "/"+tmpID;
    var writeStrm = fs.createWriteStream(path);
    dataStream.pipe(writeStrm);
    dataStream.on('end',function(d){
        var digest = Hash.arrayBuffer();
        fs.appendFile(path+"/#0",digest,function(err){
            if (err) {
                console.log(err);
            }
        });
        var newPath = path.replaceAll(tmpID,"#"+crypt.toHex(digest));
        fs.rename(path,newPath,function(err){
            if (err) {
                console.log(err);
            }
        });
    });
}
var write = function(data,adress) {
    var Hash = crypt.Keccak256(data);
    var ID = crypt.toHex(Hash);
    var path = filePath+adress;
    if (!fs.existsSync(path)) {
        fs.mkdirSync(path);
    }
    fs.appendFile(path+"/index",Hash,function(err){
        if (err) {
            console.log(err);
        }
    });
    path += "/#"+ID;
    if (fs.existsSync(path)) {
        return ID;
    }
    fs.writeFile(path,data,function(err){
        if (err) {
            console.log(err);
        }
    });
}
var Options = null;
var PrivateKey = null;
var PublicKey = null;
var Adress = null;
var filePath = null;
var stdin = fs.createReadStream(null, {fd: 3});
var stdout = fs.createWriteStream(null, {fd: 3});
var createOutputStream = function(RandID) {
    if (!RandID) {
        RandID = crypto.randomBytes(32);
    }
    return new stream.Writable({
        write: function(chunk, encoding, next) {
            stdout.write(Buffer.concat([RandID,chunk]));
            next();
        },
        final: function() {
            stdout.write(RandID);
        }
    });
}
var InputStreams = {};
var OutputStreams = {};
var StreamHandler = function(InStream,OutStream) {
    var type = -1;
    var body = Buffer.alloc(0);
    var header = Buffer.alloc(0);
    var d = {};
    InStream.on('data',function(data){
        if (type == -1) {
            type = data[0];
            data = data.slice(1);
        }
        if (type === 128) {
            body = Buffer.concat([body,data]);
        } else if (type === 129) {
            body = Buffer.concat([body,data]);
        } else if (type === 131) {
            body = Buffer.concat([body,data]);
        }
    });
    InStream.on('close',function(){
        if (type === 128) {
            var Txn = parseSignedTx(body);
            write(body,Txn.To);
            write(body,Txn.From);
            delete Txn.arrayBuffer;
            Txn.Fee = amountToString(Txn.Fee.RawTokenAmount);
            Txn.Change = amountToString(Txn.Change.RawTokenAmount);
            Txn.Amount = amountToString(Txn.Amount.RawTokenAmount);
            OutStream.end(Buffer.from(JSON.stringify(Txn),'utf-8'));
        } else if (type === 129) {
            var Msg = parseEncryptedMessage(body);
            // console.log("Message3");
            // console.log(Msg);
            write(body,Msg.To);
            delete Msg.arrayBuffer;
            if (Msg.To == Adress) {
                try {
                    Msg = decryptMessage(Msg);
                    delete Msg.Message;
                } catch(err) {
                    console.log(err);
                }
            }
            if (Msg.Message) {
                Msg.Message = Array.from(Msg.Message);
            }
            OutStream.end(Buffer.from(JSON.stringify(Msg),'utf-8'));
        } else if (type === 131) {
            var Contract = parseContract(body);
            for (var i=0; i<Contract.Terms.length; i++) {
                write(body,Contract.Terms.Adress);
            }
            delete Contract.arrayBuffer;
            OutStream.end(Buffer.from(JSON.stringify(Contract),'utf-8'));
        }
    });
    // InStream.pipe(OutStream);
}
stdin.on('data',function(data){
    if (!Options) {
        var msg = JSON.parse(data.toString('utf-8'));
        Options = msg;
        Adress = Options.Adress;
        filePath = Options.DataFilePath;
        PrivateKey = BigInt(Options.PrivateKey);
        PublicKey = crypt.secp256k1.adressToPublicKey(Options.Adress);
    } else {
        var RandIDBffr = data.subarray(0,32);
        var RandID = RandIDBffr.toString('hex');
        data = data.slice(32);
        if (!InputStreams[RandID]) {
            InputStreams[RandID] = new stream.Readable({read() {}});
            OutputStreams[RandID] = createOutputStream(RandIDBffr);
            StreamHandler(InputStreams[RandID],OutputStreams[RandID]);
            InputStreams[RandID].push(data);
        } else {
            if (data.length > 0) {
                InputStreams[RandID].push(data);
            } else {
                InputStreams[RandID].destroy();
                delete InputStreams[RandID];
            }
        }
    }
});