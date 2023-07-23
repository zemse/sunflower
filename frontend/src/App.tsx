import React, { useEffect, useState } from 'react';
import logo from './logo.svg';
// import './App.css';
import { BigNumber, BigNumberish, ethers } from 'ethers';
import { safeL1, pluginL2, optimism } from './ethers';
import { Button, Container, Form, ListGroup, Nav, NavDropdown, Navbar, Spinner } from 'react-bootstrap';
import { keccak256 } from 'ethers/lib/utils';
import axios from 'axios';



function App() {
  let [owners, setOwners] = useState<string[]>();
  useEffect(() => {
    safeL1.getOwners().then((owners: string[]) => {
      setOwners(owners);
    })
  }, [])
  
  let [pluginNonce, setPluginNonce] = useState<number>();
  useEffect(() => {
    pluginL2.pluginNonce().then((nonce: BigNumber) => {
      setPluginNonce(nonce.toNumber());
    })
  }, [])

  
  let [page, setPage] = useState<number>(1);


  // L2
  // 1 - create
  // 2 - loading
  // 3 - generating proof
  // 4 - sign in meantime
  // 5 - proof generated, submitting
  // 6 - submitted successfully
  // 7 - there was an error
  let [l2State, setL2State] = useState(1);

  let [to, setTo] = useState<string>();
  let [data, setData] = useState<string>();

  let [proof, setProof] = useState<string>();
  
  let [signA_state, set_signA_state] = useState(1);
  let [signB_state, set_signB_state] = useState(1);
  let [sigA, setSigA] = useState<string>();
  let [sigB, setSigB] = useState<string>();

  let [finalSubmitState, setFinalSubmitState] = useState(1);

  async function fetchProof() {
    // await new Promise(res => setTimeout(res, 1000));
    // return '0x12222'
    const resp = await axios.get("http://localhost:8000/gen_proof?address=0x6dC501a9911370285B3ECc2830dd481fFCDDa348", {
      timeout: 1_000_000
    })
    return resp.data
  }

  async function submit() {
    await pluginL2.connect(new ethers.Wallet(
      process.env.REACT_APP_PK_27!, optimism
   )).executeTransaction("0x0000000000000000000000000000000000000000", "0x8eB9B5F9b631a52F9c9a47F574ec9eF5d3641421", [
     to, 0, data
   ], 0, ['0x'+proof], ethers.utils.concat([sigA!, sigB!])).then(() => setFinalSubmitState(3))
  }


  function sign(is78: boolean) {
    function encodeTx(
      to: string,
      value: BigNumberish,
      data: string,
      operation: number,
      chainId: number,
      nonce: number
    ) {
      let safeTxHash = keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256", "bytes32", "uint8", "uint256"],
          [to, value, keccak256(data), operation, nonce]
        )
      );
    
      return ethers.utils.concat([
        "0x19",
        "0x01",
        ethers.utils.id("SunflowerSafePluginEthParis"),
        ethers.utils.hexZeroPad(ethers.utils.hexlify(chainId), 32),
        safeTxHash,
      ]);
    }
    if(!to) throw new Error('to address is required');
    if(!data) throw new Error('calldata is required');
    let encoded = encodeTx(
      to,
      0,
      data,
      0,
      10, // optimism
      0
    );
    
    let encodedHash = keccak256(encoded);
    
    const wallet = new ethers.Wallet(
      is78 ? process.env.REACT_APP_PK_78! : process.env.REACT_APP_PK_27!
    );
    let sig = wallet._signingKey().signDigest(encodedHash);
    return ethers.utils.joinSignature(sig)
  } 

  return (
    <div className="App">
      <Navbar bg="dark" data-bs-theme="dark">
        <Container>
          <Navbar.Brand href="#home">sunflower gnosis safe plugin demo</Navbar.Brand>
          <Nav className="me-auto">
            <Nav.Link onClick={() => setPage(1)}>L1</Nav.Link>
            <Nav.Link onClick={() => setPage(2)}>L2</Nav.Link>
          </Nav>
        </Container>
      </Navbar>

    <Container>
      {page === 1 ? <>

        <p className="mt-4">safe address on L1: <br /></p>  
        <ListGroup className="">
          <ListGroup.Item><span style={{fontFamily: "monospace"}}>0x6dC501a9911370285B3ECc2830dd481fFCDDa348</span></ListGroup.Item>
        </ListGroup>
        <p className="mt-4">l1 safe owners - 2 of 3 multisig <br /></p>  
        <ListGroup>
          {owners?.map(o => <ListGroup.Item><span style={{fontFamily: "monospace"}}>{o}</span></ListGroup.Item>)}
        </ListGroup>
      </> : null}


    {page === 2 ? <>
      <p className="mt-4">safe address on L2: <br /></p>  
        <ListGroup className="">
          <ListGroup.Item><span style={{fontFamily: "monospace"}}>0x8eB9B5F9b631a52F9c9a47F574ec9eF5d3641421</span></ListGroup.Item>
        </ListGroup>
      <p className="mt-4 mb-3">create new safe transaction on l2 with nonce {pluginNonce}</p>
      <Form>
        <Form.Group className="mb-3" controlId="formBasicEmail">
          <Form.Control type="text" placeholder="dest" onChange={e => setTo(e.target.value)} />
        </Form.Group>

        <Form.Group className="mb-3" controlId="formBasicPassword">
          <Form.Control type="text" placeholder="calldata" onChange={e => setData(e.target.value)} />
        </Form.Group>
        
        {!proof ? <>
        <Button disabled={l2State !== 1 && l2State !== 5 && !proof} variant="primary" onClick={()=> {
          fetchProof().then(data => {
            console.log(123);
            setL2State(6);
            console.log(1233);
            setProof(data);
          }).catch(e => alert(e.message))
          setL2State(2); 
          setTimeout(() => { 
            setL2State(3);
            setTimeout(() => {
              setL2State(4);
            }, 1000);
          }, 1000)}
        }>
         {l2State === 1? <>create</> : null}
         {l2State === 2? <Spinner style={{width: 20, height: 20}} /> : null}
         {(l2State === 3 || l2State === 4) && !proof? <>generating proof...</> : null}
         {l2State === 5 ? <>submit</> : null}
         {proof ? <>submit</>: null}
        </Button>
          </>: <>
            <Button  onClick={() => {
              setFinalSubmitState(2)
              submit()
            }}>{finalSubmitState===1 ? 'Submit' : finalSubmitState===2 ? 'Submitting': 'Submitted'}</Button>

          </>}




        {l2State === 4 && (!proof || !sigA || !sigB) ? <>
          <p className='mt-4'>{l2State === 4? <>in the mean time we can collect signatures:</> : null}</p>
          <Button className='ml-2' disabled={signA_state !== 1} variant="primary" onClick={() => {
            set_signA_state(2); setTimeout(() => {
              setSigA(sign(true))
              set_signA_state(3);
            }, 1000)
            }}>Sign{signA_state === 2 ? <>ing</>: null}{signA_state === 3 ? <>ed</>: null} from 0x78</Button>
          
          <Button className='mr-2' disabled={signB_state !== 1} variant="primary" onClick={() => {
            set_signB_state(2); setTimeout(() => {
              setSigB(sign(false))
              set_signB_state(3);
            }, 1000)
            }}>Sign{signB_state === 2 ? <>ing</>: null}{signB_state === 3 ? <>ed</>: null} from 0x27</Button>
          </> : null}
      </Form></> : null}

            {sigA || sigB ? <>
          <p className='mt-4'>Signatures:</p>
          <ListGroup>
            {sigA ? <ListGroup.Item><span style={{fontFamily: "monospace"}}>{sigA}</span></ListGroup.Item> : null}
            {sigB ? <ListGroup.Item><span style={{fontFamily: "monospace"}}>{sigB}</span></ListGroup.Item> : null}
          </ListGroup>
            </> : null}

            {proof ? <>
              <p className='mt-4'>proof:</p>
              <ListGroup>
                <ListGroup.Item><span style={{fontFamily: "monospace"}}>{proof}</span></ListGroup.Item>
              </ListGroup>
            </> : null}
    </Container>
    </div>
  );
}

export default App;
