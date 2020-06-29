demo:
	yarn node src/centralized_crosschain_demo.js

schema:
	mkdir -p build/
	moleculec --language - --schema-file ../ckb-contracts/schema/centralized_crosschain.mol --format json > ./build/centralized_crosschain.json
	moleculec-es -inputFile build/centralized_crosschain.json -outputFile ./build/centralized_crosschain.esm.js -generateTypeScriptDefinition
	npx rollup -f umd -i ./build/centralized_crosschain.esm.js -o build/centralized_crosschain.js --name centralized_crosschain
	cp ./build/centralized_crosschain.esm.d.ts build/centralized_crosschain.d.ts

clean:
	rm -rf build/*.{json,js,ts}

.PHONY: schema clean demo