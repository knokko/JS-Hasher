const Hasher = {
	clientHash : function(password, salt){
		const buffer = new BitHelper.ByteArrayBitOutput(new Int8Array(2 * (password.length + salt.length)));
		for(let index = 0; index < password.length; index++){
			buffer.writeChar(password.charCodeAt(index));
		}
		for(let index = 0; index < salt.length; index++){
			buffer.writeChar(salt.charCodeAt(index));
		}
		const random = createPseudoRandomArray(buffer.array);
		const hash = {
			result : random.nextInts(20)
		};
		const encryptor = random.nextInts(20);
		return {
			hashResult : hash,
			encryptor : encryptor
		};
	},
	tempHash : function(clientHash, temp1, temp2, temp3, temp4){
		const client = clientHash.result;
		const random = new RandomArray([
			new PseudoRandom(client[0], client[14], client[1], client[12], temp1, temp4, client[2], client[17]), 
				new PseudoRandom(client[3], client[19], client[4], client[10], client[5], client[15], temp2, temp3),
				new PseudoRandom(client[6], client[11], client[7], client[13], client[8], client[16], client[9], client[18])
		]);
		const arrayResult = [
			client[0] + random.nextInt() + random.nextInt() + random.nextInt(), client[7] + random.nextInt() + random.nextInt() + random.nextInt(), client[4] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[2] + random.nextInt() + random.nextInt() + random.nextInt(), client[8] + random.nextInt() + random.nextInt() + random.nextInt(), client[3] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[1] + random.nextInt() + random.nextInt() + random.nextInt(), client[6] + random.nextInt() + random.nextInt() + random.nextInt(), client[5] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[9] + random.nextInt() + random.nextInt() + random.nextInt(), client[17] + random.nextInt() + random.nextInt() + random.nextInt(), client[12] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[15] + random.nextInt() + random.nextInt() + random.nextInt(), client[19] + random.nextInt() + random.nextInt() + random.nextInt(), client[10] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[13] + random.nextInt() + random.nextInt() + random.nextInt(), client[16] + random.nextInt() + random.nextInt() + random.nextInt(), client[18] + random.nextInt() + random.nextInt() + random.nextInt(),
			client[11] + random.nextInt() + random.nextInt() + random.nextInt(), client[14] + random.nextInt() + random.nextInt() + random.nextInt()
		];
		return {
			result : arrayResult
		};
	},
	encrypt : function(clientHash, encryptor){
		const client = clientHash.result;
		const result = new Array(20);
		for(let index = 0; index < 20; index++){
			result[index] = client[index] + encryptor[index];//mimic java int overflow
			if(result[index] > 2147483647){ 
				result[index] -= 4294967296;
			}
			if(result[index] < -2147483648){
				result[index] += 4294967296;
			}
		}
		return {
			'result': result
		};
	},
	decrypt : function(encrypted, encryptor){
		const crypted = encrypted.result;
		const result = new Array(20);
		for(let index = 0; index < 20; index++){
			result[index] = crypted[index] - encryptor[index];//mimic java int overflow
			if(result[index] > 2147483647){ 
				result[index] -= 4294967296;
			}
			if(result[index] < -2147483648){
				result[index] += 4294967296;
			}
		}
		return {
			'result': result
		};
	}
};