#! /usr/bin/env -S node --no-warnings

import fs from "fs";
import {verifyReport} from './crypto/attestation.js';
import Data from './crypto/data.js'
import crypto from 'crypto'

const validateQuote = (quotePath, reportPath, expectedMRENCLAVE) => {
  fs.readFile(quotePath, (err, data) => {
    if (err) {
      console.error(err)
      return
    }

    let quote;

    verifyReport(new Data(data), {
      MRENCLAVE: expectedMRENCLAVE
    })
    .then(quote => {
      if (quote.reportBody.uniqueID.toBase64() !== expectedMRENCLAVE){
        throw new Error(`This report doesn't come from the correct MRENCLAVE. got(${quote.reportBody.uniqueID.toBase64()}) expected(${expectedMRENCLAVE})`)
      }

      fs.readFile(reportPath, async (err, data) => {
        if (err) {
          throw new Error(`could not read report (${reportPath})`)
          return;
        }
        const reportHash = await crypto.subtle.digest('SHA-256', new Uint8Array(data))
        const expectedSignedValue = Data.join([new Uint8Array(reportHash), new Uint8Array(32)]);

        if (!quote.reportBody.reportData.equals(expectedSignedValue)){
          throw new Error("The quote is valid but does'n match the report")
        }else{
          console.log('Successfull validation of enclave quote');
        }
      })
    })
    .catch(e => console.error(e, 'bad'))
  })
}

const myArgs = process.argv.slice(2);

if (myArgs.length < 3) {
  console.error('Usage: quote-validator <quote path> <report path> <MRENCLAVE>')
}else{
  const quotePath = myArgs[0]
  const reportPath = myArgs[1]
  const expectedMRENCLAVE = myArgs[2]

  if (!fs.existsSync(quotePath)) {
    console.error(`no quote (${quotePath})`)
  } else if (!fs.existsSync(reportPath)) {
    console.error(`no report (${reportPath})`)
  }else if (!/^[a-zA-Z0-9\/+=]+$/.test(expectedMRENCLAVE)) {
    console.error(`expected base64 encoded MRENCLAVE got(${expectedMRENCLAVE})`)
  }else{
    validateQuote(quotePath, reportPath, expectedMRENCLAVE)
  }
}



