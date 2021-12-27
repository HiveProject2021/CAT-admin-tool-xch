import click
import aiohttp
import asyncio
import re
import json
import time
import aiosqlite
import sqlite3
import logging
import redis

from typing import Dict, Optional, Tuple, Iterable, Union, List
from blspy import AugSchemeMPL, G2Element, PrivateKey

from chia.cmds.wallet_funcs import get_wallet
from chia.rpc.wallet_rpc_client import WalletRpcClient
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.config import load_config
from chia.util.ints import uint16
from chia.util.byte_types import hexstr_to_bytes
from chia.types.blockchain_format.program import Program
from clvm_tools.clvmc import compile_clvm_text
from clvm_tools.binutils import assemble
from chia.types.spend_bundle import SpendBundle
from chia.wallet.cc_wallet.cc_utils import (
    construct_cc_puzzle,
    CC_MOD,
    SpendableCC,
    unsigned_spend_bundle_for_spendable_ccs,
)
from chia.util.bech32m import decode_puzzle_hash

from chia.consensus.constants import ConsensusConstants
from chia.util.hash import std_hash
from chia.types.announcement import Announcement
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_spend import CoinSpend
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.condition_with_args import ConditionWithArgs
from chia.types.spend_bundle import SpendBundle
from chia.util.clvm import int_from_bytes, int_to_bytes
from chia.util.condition_tools import conditions_by_opcode, conditions_for_solution, pkm_pairs_for_conditions_dict
from chia.util.ints import uint32, uint64
from chia.util.byte_types import hexstr_to_bytes


from chia.types.blockchain_format.classgroup import ClassgroupElement
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.foliage import TransactionsInfo
from chia.types.blockchain_format.program import SerializedProgram
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.blockchain_format.slots import InfusedChallengeChainSubSlot
from chia.types.blockchain_format.vdf import VDFInfo, VDFProof
from chia.types.end_of_slot_bundle import EndOfSubSlotBundle
from chia.types.full_block import FullBlock
from chia.types.unfinished_block import UnfinishedBlock

from chia.wallet.derive_keys import master_sk_to_wallet_sk
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
    solution_for_conditions,
)
from chia.wallet.puzzles.puzzle_utils import (
    make_assert_aggsig_condition,
    make_assert_coin_announcement,
    make_assert_puzzle_announcement,
    make_assert_relative_height_exceeds_condition,
    make_assert_absolute_height_exceeds_condition,
    make_assert_my_coin_id_condition,
    make_assert_absolute_seconds_exceeds_condition,
    make_assert_relative_seconds_exceeds_condition,
    make_create_coin_announcement,
    make_create_puzzle_announcement,
    make_create_coin_condition,
    make_reserve_fee_condition,
    make_assert_my_parent_id,
    make_assert_my_puzzlehash,
    make_assert_my_amount,
)
from chia.util.keychain import Keychain, bytes_from_mnemonic, bytes_to_mnemonic, generate_mnemonic, mnemonic_to_seed

from chia.consensus.default_constants import DEFAULT_CONSTANTS

from chia.rpc.full_node_rpc_api import FullNodeRpcApi
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.config import load_config
from chia.util.ints import uint16
from chia.util.misc import format_bytes


# Loading the client requires the standard chia root directory configuration that all of the chia commands rely on
async def get_client() -> Optional[WalletRpcClient]:
    try:
        config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
        self_hostname = config["self_hostname"]
        wallet_rpc_port = config["wallet"]["rpc_port"]
        wallet_client = await WalletRpcClient.create(
            self_hostname, uint16(wallet_rpc_port), DEFAULT_ROOT_PATH, config
        )
        return wallet_client
    except Exception as e:
        if isinstance(e, aiohttp.ClientConnectorError):
            print(
                f"Connection error. Check if full node is running at {wallet_rpc_port}"
            )
        else:
            print(f"Exception from 'harvester' {e}")
        return None

async def  push_transaction(SpendBundle):  
    try:
        config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
        self_hostname = config["self_hostname"]
        full_node_rpc_port = config["full_node"]["rpc_port"]
        full_node_client = await FullNodeRpcClient.create(self_hostname, uint16(full_node_rpc_port), DEFAULT_ROOT_PATH, config)
        push_res = await full_node_client.push_tx(SpendBundle)
        return push_res
    except Exception as e:
        print(f"Exception from 'push_transaction' {e}")
        return None
    finally:
        full_node_client.close()
        await full_node_client.await_closed()

async def get_signed_tx(fingerprint, ph, amt, fee):
    try:
        wallet_client: WalletRpcClient = await get_client()
        wallet_client_f, _ = await get_wallet(wallet_client, fingerprint)
        return await wallet_client.create_signed_transaction(
            [{"puzzle_hash": ph, "amount": amt}], fee=fee
        )
    finally:
        wallet_client.close()
        await wallet_client.await_closed()


# The clvm loaders in this library automatically search for includable files in the directory './include'
def append_include(search_paths: Iterable[str]) -> List[str]:
    if search_paths:
        search_list = list(search_paths)
        search_list.append("./include")
        return search_list
    else:
        return ["./include"]


def parse_program(program: Union[str, Program], include: Iterable = []) -> Program:
    if isinstance(program, Program):
        return program
    else:
        if "(" in program:  # If it's raw clvm
            prog = Program.to(assemble(program))
        elif "." not in program:  # If it's a byte string
            prog = Program.from_bytes(hexstr_to_bytes(program))
        else:  # If it's a file
            with open(program, "r") as file:
                filestring: str = file.read()
                if "(" in filestring:  # If it's not compiled
                    # TODO: This should probably be more robust
                    if re.compile(r"\(mod\s").search(filestring):  # If it's Chialisp
                        prog = Program.to(
                            compile_clvm_text(filestring, append_include(include))
                        )
                    else:  # If it's CLVM
                        prog = Program.to(assemble(filestring))
                else:  # If it's serialized CLVM
                    prog = Program.from_bytes(hexstr_to_bytes(filestring))
        return prog


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command()
@click.pass_context
@click.option(
    "-s",
    "--solution",
    required=True,
    default="()",
    show_default=True,
    help="The solution to the TAIL program",
)
@click.option(
    "-t",
    "--send-to",
    required=True,
    help="The address these CATs will appear at once they are issued",
)
@click.option(
    "-a",
    "--amount",
    required=True,
    type=int,
    help="The amount to issue in mojos (regular XCH will be used to fund this)",
)
@click.option(
    "-m",
    "--fee",
    required=True,
    default=0,
    show_default=True,
    help="The XCH fee to use for this issuance",
)
@click.option(
    "-f",
    "--fingerprint",
    type=int,
    help="The wallet fingerprint to use as funds",
)
@click.option(
    "-sig",
    "--signature",
    multiple=True,
    help="A signature to aggregate with the transaction",
)
@click.option(
    "-as",
    "--spend",
    multiple=True,
    help="An additional spend to aggregate with the transaction",
)
@click.option(
    "-b",
    "--as-bytes",
    is_flag=True,
    help="Output the spend bundle as a sequence of bytes instead of JSON",
)
@click.option(
    "-sc",
    "--select-coin",
    is_flag=True,
    help="Stop the process once a coin from the wallet has been selected and return the coin",
)
def cli(
    ctx: click.Context,
    solution: str,
    send_to: str,
    amount: int,
    fee: int,
    fingerprint: int,
    signature: Tuple[str],
    spend: Tuple[str],
    as_bytes: bool,
    select_coin: bool,
):
    ctx.ensure_object(dict)
    
    #传递参数,固定写法,不需要更改
    tail = "./reference_tails/genesis_by_coin_id.clsp.hex"
    tail = parse_program(tail)
    
    #形成curry 原有代码写法
    curry = ()
    curried_args = [assemble(arg) for arg in curry]
    solution = parse_program(solution)
    address = decode_puzzle_hash(send_to)
    #print(curried_args)
    
    aggregated_signature = G2Element()
    for sig in signature:
        aggregated_signature = AugSchemeMPL.aggregate(
            [aggregated_signature, G2Element.from_bytes(hexstr_to_bytes(sig))]
        )

    aggregated_spend = SpendBundle([], G2Element())
    for bundle in spend:
        aggregated_spend = SpendBundle.aggregate(
            [aggregated_spend, SpendBundle.from_bytes(hexstr_to_bytes(bundle))]
        )
    curried_tail = tail
    # Construct the intermediate puzzle
    p2_puzzle = Program.to(
        (1, [[51, 0, -113, curried_tail, solution], [51, address, amount, [address]]])
    )
    # Wrap the intermediate puzzle in a CAT wrapper
    cat_puzzle = construct_cc_puzzle(CC_MOD, curried_tail.get_tree_hash(), p2_puzzle)
    cat_ph = cat_puzzle.get_tree_hash()

    # Get a signed transaction from the wallet 
    # 
    #signed_tx = asyncio.get_event_loop().run_until_complete(
    #    get_signed_tx(fingerprint, cat_ph, amount, fee) 
    #)
    #print('signed_tx------------------------------------------------------')
    #print(signed_tx.spend_bundle)
    wt = WalletTool(DEFAULT_CONSTANTS)
    signed_tx = asyncio.get_event_loop().run_until_complete(
        wt.get_signed_tx(str(cat_ph), amount, fee)
    )
    #print('signed_tx------------------------------------------------------')
    #print(signed_tx)
    #print('additions------------------------------------------------------')
    #print(signed_tx.additions())
    #print('removals------------------------------------------------------')
    #print(signed_tx.removals())
    
    eve_coin = list(
        filter(lambda c: c.puzzle_hash == cat_ph, signed_tx.additions())
    )[0]
    print('eve_coin 生成CAT的那个COIN------------------------------------------------------')
    print(eve_coin)
    primary_coin = list(
            filter(lambda c: c.name() == eve_coin.parent_coin_info, signed_tx.removals())
        )[0]
    print('primary_coin 选中要支付的COIN,只能选择一个--------------------------------------')
    print(primary_coin)
    #print(json.dumps(primary_coin.to_json_dict(), sort_keys=True, indent=4))
    print('primary_coin.name() 选中要支付的COIN 的名称--------------------------------------')
    print(f"Name: {primary_coin.name()}")
    #此处代码以上的主要目标是为了获得用来做CAT的那个COIN的NAME
    #return 
    
    curry = tuple(['0x'+str(primary_coin.name())])
    print(curry)
    if(len(curry)==0):
        print("NO COIN TO CURRY")
        print("*********************") 
        return ''
        
    curried_args = [assemble(arg) for arg in curry]
    solution = parse_program(solution)
    address = decode_puzzle_hash(send_to)
    #print(curried_args)
    
    aggregated_signature = G2Element()
    for sig in signature:
        aggregated_signature = AugSchemeMPL.aggregate(
            [aggregated_signature, G2Element.from_bytes(hexstr_to_bytes(sig))]
        )

    aggregated_spend = SpendBundle([], G2Element())
    for bundle in spend:
        aggregated_spend = SpendBundle.aggregate(
            [aggregated_spend, SpendBundle.from_bytes(hexstr_to_bytes(bundle))]
        )

    # Construct the TAIL
    if len(curried_args) > 0:
        curried_tail = tail.curry(*curried_args)
    else:
        curried_tail = tail
    #print('curried_tail.get_tree_hash()-----------------------------------------------')
    #print(curried_tail.get_tree_hash())
    #return 
    
    # Construct the intermediate puzzle
    p2_puzzle = Program.to(
        (1, [[51, 0, -113, curried_tail, solution], [51, address, amount, [address]]])
    )

    # Wrap the intermediate puzzle in a CAT wrapper
    cat_puzzle = construct_cc_puzzle(CC_MOD, curried_tail.get_tree_hash(), p2_puzzle)
    cat_ph = cat_puzzle.get_tree_hash()

    # Get a signed transaction from the wallet
    #signed_tx = asyncio.get_event_loop().run_until_complete(
    #    get_signed_tx(fingerprint, cat_ph, amount, fee)
    #)
    wt = WalletTool(DEFAULT_CONSTANTS)
    signed_tx = asyncio.get_event_loop().run_until_complete(
        wt.get_signed_tx(str(cat_ph), amount, fee)
    )
    eve_coin = list(
        filter(lambda c: c.puzzle_hash == cat_ph, signed_tx.additions())
    )[0]
    

    # Create the CAT spend
    spendable_eve = SpendableCC(
        eve_coin,
        curried_tail.get_tree_hash(),
        p2_puzzle,
        Program.to([]),
        limitations_solution=solution,
        limitations_program_reveal=curried_tail,
    )
    eve_spend = unsigned_spend_bundle_for_spendable_ccs(CC_MOD, [spendable_eve])

    # Aggregate everything together
    final_bundle = SpendBundle.aggregate(
        [
            signed_tx,
            eve_spend,
            aggregated_spend,
            SpendBundle([], aggregated_signature),
        ]
    )
    
    #print(final_bundle)
    push_transaction_result = asyncio.get_event_loop().run_until_complete(
        push_transaction(final_bundle)
    )
    if curried_tail.get_tree_hash() is not None:
        push_transaction_result['AssetID'] = str(curried_tail.get_tree_hash())
        
    if push_transaction_result is None:
        print("Next Coin Name Will Be Used.")
    else:
        print("每一个CAT的生成需要3-5分钟的时间间隔来让区块进行打包,不然会有其中一个CAT会因为选择了同样的COIN,导致创建失败")
        print(push_transaction_result) 
        
    #if as_bytes:
    #    final_bundle = bytes(final_bundle).hex()
    #else:
    #    final_bundle = json.dumps(final_bundle)
            
    #得到一个可用的币的NAME--结束
    


class WalletTool:
    next_address = 0
    pubkey_num_lookup: Dict[bytes, uint32] = {}

    def __init__(self, constants: ConsensusConstants, sk: Optional[PrivateKey] = None):
        
        
        self.constants = constants
        self.current_balance = 0
        self.my_utxos: set = set()
        self.generator_lookups: Dict = {}
        self.puzzle_pk_cache: Dict = {}
        
        #print(constants)
        #print()
        #print()
        #print()
     
    async def  get_signed_tx(self,SendToPuzzleHash,SendToAmount,fee):           
        #mnemonic = generate_mnemonic()
        #when you want to make a send transaction, you must need a account.
        #here it is to fill the mnemonic works and to make a account
        mnemonic = "lazy shift success orange tenant vacuum high song rack creek differ mixed cotton pass claim track industry magic urge casual guilt room simple stuff"
        entropy = bytes_from_mnemonic(mnemonic)
        seed = mnemonic_to_seed(mnemonic, "")
        self.private_key = AugSchemeMPL.key_gen(seed)
        fingerprint = self.private_key.get_g1().get_fingerprint()
        
        #得到指定账户的300个地址.
        AllPuzzleHashArray = []
        for i in range(0, 50):
            pubkey = master_sk_to_wallet_sk(self.private_key, i).get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            puzzle_hash = str(puzzle.get_tree_hash())
            AllPuzzleHashArray.append(puzzle_hash);
            
        #print(AllPuzzleHashArray)
        #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
        separator = "','"
        AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
        AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
        
        
        #连接数据库
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("/home/wang/.chia/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
        
        #手工输入来构建参数部分代码
        #SendToAmount = uint64(60000)
        #fee = uint64(0)
        #SendToPuzzleHash = "1d2ea2855c783f2790168f9eb88ac0a4e4c1468b9e25338efbb944161d0710b3"
        #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
        
        #查询未花费记录
        #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
        cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
        rows = await cursor.fetchall()
        coinList = []
        CurrentCoinAmount = 0
        for row in rows:
            coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
            CurrentCoinAmount = uint64.from_bytes(row[7])
            coinList.append(coin)
            #print(row) 
            #构建CAT时,只能选择一个COIN,不能通过选择多个COIN来累计金额的形式实现.
            if(CurrentCoinAmount>SendToAmount):
                break
        #print(rows)
        await cursor.close()
        await db_connection.close()
        if(len(coinList)==0):
            return ''
        
        #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
        generate_signed_transaction = self.generate_signed_transaction_multiple_coins(
            SendToAmount,
            SendToPuzzleHash,
            coinList,
            {},
            fee,
        )
        return generate_signed_transaction
        
        #提交交易记录到区块链网络
        #await self.push_tx(generate_signed_transaction)
        
        #print("===================================================")        
        #ResultStr = str(generate_signed_transaction)
        #ResultStrValue = ResultStr.replace("\'","\"")
        #print("curl --insecure --cert ~/.chia/mainnet/config/ssl/full_node/private_full_node.crt --key ~/.chia/mainnet/config/ssl/full_node/private_full_node.key -d '{        \"spend_bundle\":")
        #print(ResultStrValue)
        #print("}' -H \"Content-Type: application/json\" -X POST https://localhost:9755/push_tx")
        #print("===================================================")   
    
    async def GetAllAddress(self):    
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("~/.chia/mainnet/db/blockchain_v1_mainnet.sqlite")
        
        cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", (coin_name,))
        row = await cursor.fetchone()
        await cursor.close() 
    
    async def GetAllUnSpentCoins(self):    
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("~/.chia/mainnet/db/blockchain_v1_mainnet.sqlite")
        
        cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", (coin_name,))
        row = await cursor.fetchone()
        await cursor.close()  
        
    async def push_tx(self,generate_signed_transaction):
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx(generate_signed_transaction)
            print(push_res)
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
        
            
    def get_next_address_index(self) -> uint32:
        self.next_address = uint32(self.next_address + 1)
        return self.next_address

    def get_private_key_for_puzzle_hash(self, puzzle_hash: bytes32) -> PrivateKey:
        if puzzle_hash in self.puzzle_pk_cache:
            child = self.puzzle_pk_cache[puzzle_hash]
            private = master_sk_to_wallet_sk(self.private_key, uint32(child))
            #  pubkey = private.get_g1()
            return private
        else:
            for child in range(0,300):
                pubkey = master_sk_to_wallet_sk(self.private_key, uint32(child)).get_g1()
                #print(type(puzzle_hash))
                #print(type(puzzle_for_pk(bytes(pubkey)).get_tree_hash()))
                #print(puzzle_hash)
                if puzzle_hash == puzzle_for_pk(bytes(pubkey)).get_tree_hash():
                    #print('===================')
                    return master_sk_to_wallet_sk(self.private_key, uint32(child))
        raise ValueError(f"Do not have the keys for puzzle hash {puzzle_hash}")

    def puzzle_for_pk(self, pubkey: bytes) -> Program:
        return puzzle_for_pk(pubkey)

    def get_new_puzzle(self) -> bytes32:
        next_address_index: uint32 = self.get_next_address_index()
        pubkey = master_sk_to_wallet_sk(self.private_key, next_address_index).get_g1()
        self.pubkey_num_lookup[bytes(pubkey)] = next_address_index

        puzzle = puzzle_for_pk(bytes(pubkey))

        self.puzzle_pk_cache[puzzle.get_tree_hash()] = next_address_index
        return puzzle

    def get_new_puzzlehash(self) -> bytes32:
        puzzle = self.get_new_puzzle()
        return puzzle.get_tree_hash()

    def sign(self, value: bytes, pubkey: bytes) -> G2Element:
        privatekey: PrivateKey = master_sk_to_wallet_sk(self.private_key, self.pubkey_num_lookup[pubkey])
        return AugSchemeMPL.sign(privatekey, value)

    def make_solution(self, condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]]) -> Program:
        ret = []

        for con_list in condition_dic.values():
            for cvp in con_list:
                if cvp.opcode == ConditionOpcode.CREATE_COIN:
                    ret.append(make_create_coin_condition(cvp.vars[0], cvp.vars[1], None))
                if cvp.opcode == ConditionOpcode.CREATE_COIN_ANNOUNCEMENT:
                    ret.append(make_create_coin_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT:
                    ret.append(make_create_puzzle_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.AGG_SIG_UNSAFE:
                    ret.append(make_assert_aggsig_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT:
                    ret.append(make_assert_coin_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT:
                    ret.append(make_assert_puzzle_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_SECONDS_ABSOLUTE:
                    ret.append(make_assert_absolute_seconds_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_SECONDS_RELATIVE:
                    ret.append(make_assert_relative_seconds_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_COIN_ID:
                    ret.append(make_assert_my_coin_id_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE:
                    ret.append(make_assert_absolute_height_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_HEIGHT_RELATIVE:
                    ret.append(make_assert_relative_height_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.RESERVE_FEE:
                    ret.append(make_reserve_fee_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_PARENT_ID:
                    ret.append(make_assert_my_parent_id(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_PUZZLEHASH:
                    ret.append(make_assert_my_puzzlehash(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_AMOUNT:
                    ret.append(make_assert_my_amount(cvp.vars[0]))
        return solution_for_conditions(Program.to(ret))

    def generate_unsigned_transaction(
        self,
        amount: uint64,
        new_puzzle_hash: bytes32,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]],
        fee: int = 0,
        secret_key: Optional[PrivateKey] = None,
    ) -> List[CoinSpend]:
        spends = []
        
        spend_value = sum([c.amount for c in coins])

        if ConditionOpcode.CREATE_COIN not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN] = []
        if ConditionOpcode.CREATE_COIN_ANNOUNCEMENT not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT] = []

        output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(new_puzzle_hash), int_to_bytes(amount)])
        condition_dic[output.opcode].append(output)
        amount_total = sum(int_from_bytes(cvp.vars[1]) for cvp in condition_dic[ConditionOpcode.CREATE_COIN])
        change = spend_value - amount_total - fee
        if change > 0:
            change_puzzle_hash = self.get_new_puzzlehash()
            change_output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [change_puzzle_hash, int_to_bytes(change)])
            condition_dic[output.opcode].append(change_output)

        secondary_coins_cond_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = dict()
        secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT] = []
        
        for n, coin in enumerate(coins):
            puzzle_hash = coin.puzzle_hash
            #print(n);
            #print(coin);
            #print('----------------------')
            if secret_key is None:
                secret_key = self.get_private_key_for_puzzle_hash(puzzle_hash)
            pubkey = secret_key.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            if n == 0:
                message_list = [c.name() for c in coins]
                for outputs in condition_dic[ConditionOpcode.CREATE_COIN]:
                    message_list.append(Coin(coin.name(), outputs.vars[0], int_from_bytes(outputs.vars[1])).name())
                message = std_hash(b"".join(message_list))
                condition_dic[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT].append(
                    ConditionWithArgs(ConditionOpcode.CREATE_COIN_ANNOUNCEMENT, [message])
                )
                primary_announcement_hash = Announcement(coin.name(), message).name()
                secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT].append(
                    ConditionWithArgs(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT, [primary_announcement_hash])
                )
                main_solution = self.make_solution(condition_dic)
                spends.append(CoinSpend(coin, puzzle, main_solution))
            else:
                spends.append(CoinSpend(coin, puzzle, self.make_solution(secondary_coins_cond_dic)))
        return spends

    def sign_transaction(self, coin_solutions: List[CoinSpend]) -> SpendBundle:
        signatures = []
        solution: Program
        puzzle: Program
        for coin_solution in coin_solutions:  # type: ignore # noqa
            secret_key = self.get_private_key_for_puzzle_hash(coin_solution.coin.puzzle_hash)
            synthetic_secret_key = calculate_synthetic_secret_key(secret_key, DEFAULT_HIDDEN_PUZZLE_HASH)
            err, con, cost = conditions_for_solution(
                coin_solution.puzzle_reveal, coin_solution.solution, self.constants.MAX_BLOCK_COST_CLVM
            )
            if not con:
                raise ValueError(err)
            conditions_dict = conditions_by_opcode(con)

            for _, msg in pkm_pairs_for_conditions_dict(
                conditions_dict, bytes(coin_solution.coin.name()), self.constants.AGG_SIG_ME_ADDITIONAL_DATA
            ):
                signature = AugSchemeMPL.sign(synthetic_secret_key, msg)
                signatures.append(signature)
        aggsig = AugSchemeMPL.aggregate(signatures)
        spend_bundle = SpendBundle(coin_solutions, aggsig)
        return spend_bundle

    def generate_signed_transaction(
        self,
        amount: uint64,
        new_puzzle_hash: bytes32,
        coin: Coin,
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = None,
        fee: int = 0,
    ) -> SpendBundle:
        if condition_dic is None:
            condition_dic = {}
        transaction = self.generate_unsigned_transaction(amount, new_puzzle_hash, [coin], condition_dic, fee)
        assert transaction is not None
        return self.sign_transaction(transaction)

    def generate_signed_transaction_multiple_coins(
        self,
        amount: uint64,
        new_puzzle_hash: bytes32,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = None,
        fee: int = 0,
    ) -> SpendBundle:
        if condition_dic is None:
            condition_dic = {}
        transaction = self.generate_unsigned_transaction(amount, new_puzzle_hash, coins, condition_dic, fee)
        assert transaction is not None
        return self.sign_transaction(transaction)


def main():
    cli()

if __name__ == "__main__":
    main()
