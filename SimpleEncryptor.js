Hasher.SimpleEncryptor = function(random){
    this.random = random;
};

Hasher.SimpleEncryptor.prototype.MIN_LENGTH = 40;
Hasher.SimpleEncryptor.prototype.HEADER_LENGTH = 5 * 4;

Hasher.SimpleEncryptor.prototype.encrypt = function(payload){
    const importantSize = payload.length + this.HEADER_LENGTH;
    const size = Math.max(importantSize, this.MIN_LENGTH);
    const data = new Int8Array(size);
    const payloadLength = payload.length;

    // Easiest way to mimic java int overflow
    const intBuffer = new Int32Array(2);
    intBuffer[1] = 1;
    for (let index = 0; index < payloadLength; index++){
        intBuffer[0] += payload[index];
        intBuffer[1] *= payload[index] + 129;
    }
    const payloadSum = intBuffer[0];
    const payloadProduct = intBuffer[1];

    const headerIndex = this.random.fastNextInt(size - this.HEADER_LENGTH + 1);
    const payloadLengthIndex = headerIndex;
    const payloadSumIndex = headerIndex + 4;
    const payloadProductIndex = headerIndex + 8;
    const dataSumIndex = headerIndex + 12;
    const dataProductIndex = headerIndex + 16;

    this.putInt(data, payloadLength, payloadLengthIndex);
    this.putInt(data, payloadSum, payloadSumIndex);
    this.putInt(data, payloadProduct, payloadProductIndex);

    for (let index = 0; index < size; index++){
        data[index] += this.random.nextByte();
    }

    const permutation = this.randomPermutation(payloadLength);
    for (let index = 0; index < payloadLength; index++){
        if (permutation[index] >= headerIndex){
            data[permutation[index] + this.HEADER_LENGTH] += payload[index];
        } else {
            data[permutation[index]] += payload[index];
        }
    }

    // mimic java int overflow
    intBuffer[0] = 0;
    intBuffer[1] = 1;
    for (let index = 0; index < size; index++){
        intBuffer[0] += data[index];
        intBuffer[1] *= data[index] + 129;
    }
    const dataSum = intBuffer[0];
    const dataProduct = intBuffer[1];

    this.increaseInt(data, dataSum, dataSumIndex);
    this.increaseInt(data, dataProduct, dataProductIndex);

    return data;
};

Hasher.SimpleEncryptor.prototype.decrypt = function(data){
    const size = data.length;
    const headerIndex = this.random.fastNextInt(size - this.HEADER_LENGTH + 1);
    const payloadLengthIndex = headerIndex;
    const payloadSumIndex = headerIndex + 4;
    const payloadProductIndex = headerIndex + 8;
    const dataSumIndex = headerIndex + 12;
    const dataProductIndex = headerIndex + 16;

    const adders = new Int8Array(size);
    for (let index = 0; index < size; index++){
        adders[index] += this.random.nextByte();
    }

    const decryptedData = new Int8Array(size);
    for (let index = 0; index < size; index++){
        decryptedData[index] = data[index] - adders[index];
    }

    const dataSum = this.getInt(decryptedData, dataSumIndex);
    const dataProduct = this.getInt(decryptedData, dataProductIndex);
    const payloadLength = this.getInt(decryptedData, payloadLengthIndex);
    const payloadSum = this.getInt(decryptedData, payloadSumIndex);
    const payloadProduct = this.getInt(decryptedData, payloadProductIndex);

    this.decreaseInt(data, dataSum, dataSumIndex);
    this.decreaseInt(data, dataProduct, dataProductIndex);

    // mimic java int overflow
    const intBuffer = new Int32Array(2);
    intBuffer[1] = 1;
    for (let index = 0; index < size; index++){
        intBuffer[0] += data[index];
        intBuffer[1] *= data[index] + 129;
    }
    const checkDataSum = intBuffer[0];
    const checkDataProduct = intBuffer[1];

    if (checkDataSum !== dataSum){
        console.log('The read data sum (' + dataSum + ') does not match the counted data sum (' + checkDataSum + ')!');
        return null;
    }
    if (checkDataProduct !== dataProduct){
        console.log('The read data product (' + dataProduct + ') does not match the calculated data product (' + checkDataProduct + ')!');
        return null;
    }

    const payload = new Int8Array(payloadLength);

    const permutation = this.randomPermutation(payloadLength);
    for (let index = 0; index < payloadLength; index++){
        if (permutation[index] >= headerIndex){
            payload[index] = decryptedData[permutation[index] + this.HEADER_LENGTH];
        } else {
            payload[index] = decryptedData[permutation[index]];
        }
    }

    // mimic java int overflow
    intBuffer[0] = 0;
    intBuffer[1] = 1;
    for (let index = 0; index < payloadLength; index++){
        intBuffer[0] += payload[index];
        intBuffer[1] *= payload[index] + 129;
    }
    const checkPayloadSum = intBuffer[0];
    const checkPayloadProduct = intBuffer[1];

    if (checkPayloadSum !== payloadSum){
        console.log('The read payload sum (' + payloadSum + ') does not match the counted payload sum (' + checkPayloadSum + ')!');
        return null;
    }

    if (checkPayloadProduct !== payloadProduct){
        console.log('The read payload product (' + payloadProduct + ') does not match the calculated payload product (' + checkPayloadProduct + ')!');
        return null;
    }

    return payload;
};

Hasher.SimpleEncryptor.prototype.randomPermutation = function(length){
    const array = new Int32Array(length);

    for (let index = 0; index < length; index++){
        array[index] = index;
    }

    for (let index = 0; index < length; index++){
        const next = this.random.fastNextInt(length - index) + index;
        const old = array[next];
        array[next] = array[index];
        array[index] = old;
    }

    return array;
};

Hasher.SimpleEncryptor.prototype.putInt = function(data, value, index){
    data[index] = BitHelper.int0(value);
    data[++index] = BitHelper.int1(value);
    data[++index] = BitHelper.int2(value);
    data[++index] = BitHelper.int3(value);
};

Hasher.SimpleEncryptor.prototype.increaseInt = function(data, value, index){
    data[index] += BitHelper.int0(value);
    data[++index] += BitHelper.int1(value);
    data[++index] += BitHelper.int2(value);
    data[++index] += BitHelper.int3(value);
};

Hasher.SimpleEncryptor.prototype.decreaseInt = function(data, value, index){
    data[index] -= BitHelper.int0(value);
    data[++index] -= BitHelper.int1(value);
    data[++index] -= BitHelper.int2(value);
    data[++index] -= BitHelper.int3(value);
};

Hasher.SimpleEncryptor.prototype.getInt = function(data, index){
    return BitHelper.makeInt(data[index], data[++index], data[++index], data[++index]);
};