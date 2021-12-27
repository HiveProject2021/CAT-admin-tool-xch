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
    #连接REDIS
    pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
    r = redis.Redis(connection_pool=pool)        
    #得到一个可用的币的NAME--开始
    mnemonic = "lazy shift success orange tenant vacuum high song rack creek differ mixed cotton pass claim track industry magic urge casual guilt room simple stuff"
    entropy = bytes_from_mnemonic(mnemonic)
    seed = mnemonic_to_seed(mnemonic, "")
    private_key = AugSchemeMPL.key_gen(seed)
    fingerprint = private_key.get_g1().get_fingerprint()    
    #得到指定账户的300个地址.
    AllPuzzleHashArray = []
    for i in range(0, 100):
        pubkey = master_sk_to_wallet_sk(private_key, i).get_g1()
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
    db_connection = asyncio.get_event_loop().run_until_complete(
        aiosqlite.connect("/home/wang/.chia/standalone_wallet/db/blockchain_v1_mainnet.sqlite")    
    )
    #手工输入来构建参数部分代码
    CatAmountMojo = uint64(amount)
    fee = uint64(0)
    #查询未花费记录
    cursor = asyncio.get_event_loop().run_until_complete(
        db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
    )
    rows = asyncio.get_event_loop().run_until_complete(
        cursor.fetchall()
    )
    print(rows)
    coinList = []
    CurrentCoinAmount = 0
    CurrentCoinAmountTotal = 0
    #curry不需要从参数中获得,直接在数据表中获取一个未花费的COIN
    curry    = ()
    for row in rows:
        CurrentCoinAmountTotal = uint64.from_bytes(row[7])
    print("TotalAmount===================") 
    print(CurrentCoinAmountTotal)
    print("==============================") 
    
    for row in rows:
        coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
        CurrentCoinAmount = uint64.from_bytes(row[7])
        coinList.append(coin)
        print("-----------------") 
        print(row[5])
        print(CurrentCoinAmount)
        print("-----------------") 
        #print(row)
        #只取一个超过指定金额的COIN
        GetCoinNameFromRedis = r.hget("CHVIES_CAT_MAKING_COIN_NAME_USED",coin.name())
        #  and GetCoinNameFromRedis is None
        if(CurrentCoinAmount>=CatAmountMojo):
            #传递参数,固定写法,不需要更改
            tail = "./reference_tails/genesis_by_coin_id.clsp.hex"
            tail = parse_program(tail)
            
            curry = tuple(['0x'+row[0]])
            r.hset("CHVIES_CAT_MAKING_COIN_NAME_USED", coin.name(), str(time.time()) )
            
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
            signed_tx = asyncio.get_event_loop().run_until_complete(
                get_signed_tx(fingerprint, cat_ph, amount, fee)
            )
            print('additions------------------------------------------------------')
            print(signed_tx.spend_bundle.additions())
            print('removals------------------------------------------------------')
            print(signed_tx.spend_bundle.removals())
            
            eve_coin = list(
                filter(lambda c: c.puzzle_hash == cat_ph, signed_tx.spend_bundle.additions())
            )[0]
            print('eve_coin------------------------------------------------------')
            print(eve_coin)
            primary_coin = list(
                    filter(lambda c: c.name() == eve_coin.parent_coin_info, signed_tx.spend_bundle.removals())
                )[0]
            print('primary_coin------------------------------------------------------')
            print(primary_coin)
            #print(json.dumps(primary_coin.to_json_dict(), sort_keys=True, indent=4))
            print('primary_coin.name()-----------------------------------------------')
            print(f"Name: {primary_coin.name()}")
            break;
            
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

            # Construct the intermediate puzzle
            p2_puzzle = Program.to(
                (1, [[51, 0, -113, curried_tail, solution], [51, address, amount, [address]]])
            )

            # Wrap the intermediate puzzle in a CAT wrapper
            cat_puzzle = construct_cc_puzzle(CC_MOD, curried_tail.get_tree_hash(), p2_puzzle)
            cat_ph = cat_puzzle.get_tree_hash()

            # Get a signed transaction from the wallet
            signed_tx = asyncio.get_event_loop().run_until_complete(
                get_signed_tx(fingerprint, cat_ph, amount, fee)
            )
            eve_coin = list(
                filter(lambda c: c.puzzle_hash == cat_ph, signed_tx.spend_bundle.additions())
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
                    signed_tx.spend_bundle,
                    eve_spend,
                    aggregated_spend,
                    SpendBundle([], aggregated_signature),
                ]
            )
            
            #print(final_bundle)
            push_transaction_result = asyncio.get_event_loop().run_until_complete(
                push_transaction(final_bundle)
            )
            if curried_tail.get_tree_hash() is None:
                push_transaction_result['AssetID'] = curried_tail.get_tree_hash()
                
            if push_transaction_result is None:
                print("Next Coin Name Will Be Used.")
            else:
                print(push_transaction_result) 
                break;
                
            #if as_bytes:
            #    final_bundle = bytes(final_bundle).hex()
            #else:
            #    final_bundle = json.dumps(final_bundle)
            
    asyncio.get_event_loop().run_until_complete( cursor.close() )
    asyncio.get_event_loop().run_until_complete( db_connection.close() )
    if(len(coinList)==0):
        print("NO COIN CAN SELECT")
        print("*********************") 
        return ''
    #得到一个可用的币的NAME--结束
    


def main():
    cli()

if __name__ == "__main__":
    main()
