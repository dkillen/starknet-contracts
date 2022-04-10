# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.math import assert_not_zero, assert_lt
from starkware.cairo.common.uint256 import Uint256, uint256_check

from openzeppelin.utils.constants import TRUE, FALSE, UINT8_MAX
from openzeppelin.security.safemath import uint256_checked_add, uint256_checked_sub_le

#
# EVents
#
@event
func Transfer(from_ : felt, to : felt, value : Uint256):
end

@event
func Approval(owner : felt, spender : felt, value : Uint256):
end

@event
func Burned(account : felt, value : Uint256):
end

@event
func OwnershipChange(previous_owner : felt, new_owner : felt):
end

@event
func Paused(status : felt):
end

#
# Storage
#
@storage_var
func name_() -> (name : felt):
end

@storage_var
func symbol_() -> (symbol : felt):
end

@storage_var
func decimals_() -> (decimals : felt):
end

@storage_var
func paused_() -> (paused : felt):
end

@storage_var
func contract_owner() -> (owner : felt):
end

@storage_var
func total_supply() -> (total_supply : Uint256):
end

@storage_var
func balances(account : felt) -> (balance : Uint256):
end

@storage_var
func allowances(owner : felt, spender : felt) -> (allowance : Uint256):
end

#
# Contract constructor
#
@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        name : felt, symbol : felt, decimals : felt, initial_supply : Uint256, recipient : felt,
        owner : felt):
    name_.write(name)
    symbol_.write(symbol)

    # Contract decimals cannot exceed 2^8, so we check
    with_attr error_message("ERC30: decimals exceed 2^8"):
        assert_lt(decimals, UINT8_MAX)
    end
    decimals_.write(decimals)

    # mint the initial supply of tokens to the recipient account
    _mint(recipient, initial_supply)

    # THe contract owner cannot be set to the zero address, so we check
    with_attr error_message("ERC20: owner cannot be the zero address"):
        assert_not_zero(owner)
    end
    contract_owner.write(owner)

    return ()
end

#
# Getters
#
@view
func name{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (name : felt):
    let (name) = name_.read()
    return (name=name)
end

@view
func symbol{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (symbol : felt):
    let (symbol) = symbol_.read()
    return (symbol=symbol)
end

@view
func totalSupply{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        totalSupply : Uint256):
    let (totalSupply : Uint256) = total_supply.read()
    return (totalSupply=totalSupply)
end

@view
func getOwner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        owner : felt):
    let (owner) = contract_owner.read()
    return (owner=owner)
end

@view
func decimals{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        decimals : felt):
    let (decimals) = decimals_.read()
    return (decimals=decimals)
end

@view
func paused{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (paused : felt):
    let (paused) = paused_.read()
    return (paused=paused)
end

@view
func balanceOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        account : felt) -> (balance : Uint256):
    let (balance : Uint256) = balances.read(account)
    return (balance=balance)
end

@view
func allowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt, spender : felt) -> (remaining : Uint256):
    let (remaining : Uint256) = allowance(owner, spender)
    return (remaining=remaining)
end

#
# Externals
#

# A function to make a transfer by the holder/owner of tokens
@external
func transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, amount : Uint256) -> (success : felt):
    _when_not_paused()
    let (sender) = get_caller_address()

    # after we have retrieved the address of the caller, we use our
    # internal _transfer function to transfer the tokens to the recipient
    _transfer(sender, recipient, amount)

    return (TRUE)
end

# A function to make a transfer by an account that has been approved up to a
# certain amount
@external
func transferFrom{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        sender : felt, recipient : felt, amount : Uint256) -> (success : felt):
    alloc_locals
    _when_not_paused()
    let (caller) = get_caller_address()
    let (caller_allowance : Uint256) = allowances.read(owner=sender, spender=caller)

    # Limit the transfer to an amount less than or equal to the approved
    # allowance and then update the spender's allowance
    with_attr error_message("ERC20: transfer amount exceeds allowance"):
        let (new_allowance : Uint256) = uint256_checked_sub_le(caller_allowance, amount)
    end
    allowances.write(sender, caller, new_allowance)

    # After we have the caller and updated the allowance, we use the
    # internal _transfer function to transfer the tokens to the recipient
    _transfer(sender, recipient, amount)

    return (TRUE)
end

# A function to approve an account, the spender, to make transfers up to the
# specified amount on behalf of the caller
@external
func approve{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, amount : Uint256) -> (success : felt):
    _when_not_paused()
    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: amount is not a valid Uint256"):
        uint256_check(amount)
    end

    # The zero address cannot approve any transfers, so we check
    let (caller) = get_caller_address()
    with_attr error_message("ERC20: zero address cannot approve"):
        assert_not_zero(caller)
    end

    # The zero address cannot be the spender, so we check
    with_attr error_message("ERC20: cannot approve to the zero address"):
        assert_not_zero(spender)
    end

    # Update the spender's allowance and emit the Approval event
    allowances.write(caller, spender, amount)
    Approval.emit(caller, spender, amount)

    return (TRUE)
end

# A function to increase a spender's approved allowance
@external
func increaseAllowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, added_value : Uint256) -> (success : felt):
    _when_not_paused()
    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: added value is not a valid Uint256"):
        uint256_check(added_value)
    end

    # Get the spenders currently approved allowance - we need the caller's
    # address to do so
    let (caller) = get_caller_address()
    let (current_allowance : Uint256) = allowances.read(caller, spender)

    # Check that the new allowance is within bounds and add to the spenders
    # approved allowance
    with_attr error_message("ERC20: allowance overflow"):
        let (new_allowance : Uint256) = uint256_checked_add(current_allowance, added_value)
    end

    # Approve the spender's new allowance
    approve(spender, new_allowance)

    return (TRUE)
end

# A function to decrease a spender's approved allowance
@external
func decreaseAllowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, substracted_value : Uint256) -> (success : felt):
    alloc_locals
    _when_not_paused()

    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: substracted_value is not a valid Uint256"):
        uint256_check(substracted_value)
    end

    # Get the spenders currently approved allowance - we need the caller's
    # address to do so
    let (caller) = get_caller_address()
    let (current_allowance : Uint256) = allowances.read(owner=caller, spender=spender)

    # Subtract from the spender's currently approved allowance
    with_attr error_message("ERC20: allowance below zero"):
        let (new_allowance : Uint256) = uint256_checked_sub_le(current_allowance, substracted_value)
    end

    # Approve the spender's new allowance
    approve(spender, new_allowance)

    return (TRUE)
end

# A function to mint tokens. It can be called by the contract owner at any time
# to mint further tokens following the initial mint. Calls the contract's
# internal mint function
@external
func mint{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, amount : Uint256):
    _only_owner()
    _mint(recipient, amount)
    return ()
end

# A function to allow a token holder to burn their tokens
@external
func burn{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(amount : Uint256):
    alloc_locals
    _when_not_paused()

    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: amount is not a valid Uint256"):
        uint256_check(amount)
    end

    # The zero address cannot burn tokens, so we check
    let (account) = get_caller_address()
    with_attr error_message("ERC20: cannot burn from the zero address"):
        assert_not_zero(account)
    end

    # The account cannot burn more tokens than it has, so we check and then
    # subtract the tokens from the account's balance
    let (balance : Uint256) = balances.read(account)
    with_attr error_message("ERC20: burn amount exceeds balance"):
        let (new_balance : Uint256) = uint256_checked_sub_le(balance, amount)
    end
    balances.write(account, new_balance)

    # Reduce the total supply by the amount burned and emit the Burned event
    let (supply : Uint256) = total_supply.read()
    let (new_supply : Uint256) = uint256_checked_sub_le(supply, amount)
    total_supply.write(new_supply)
    Burned.emit(account, amount)

    return ()
end

# A function to allow an approved account to burn tokens up to a certain amount
@external
func burnFrom{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        account : felt, amount : Uint256):
    alloc_locals
    _when_not_paused()

    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: amount is not a valid Uint256"):
        uint256_check(amount)
    end

    # The spender cannot burn more than the allowance, so we check and then
    # update the spenders allowance
    let (caller) = get_caller_address()
    let (caller_allowance : Uint256) = allowances.read(owner=account, spender=caller)
    with_attr error_message("ERC20: burn amount exceeds allowance"):
        let (new_allowance : Uint256) = uint256_checked_sub_le(caller_allowance, amount)
    end
    allowances.write(account, caller, new_allowance)

    # The spender cannot burn more tokens that the account has, so we check
    # and then update the account's balance
    let (balance : Uint256) = balances.read(account)
    with_attr error_message("ERC20: burn amount exceeds balance"):
        let (new_balance : Uint256) = uint256_checked_sub_le(balance, amount)
    end
    balances.write(account, new_balance)

    # Reduce the total supply by the amount burned and emit the Burned event
    let (supply : Uint256) = total_supply.read()
    let (new_supply : Uint256) = uint256_checked_sub_le(supply, amount)
    total_supply.write(new_supply)
    Burned.emit(account, amount)

    return ()
end

# A function to transfer ownership of the contract
@external
func transferOwnership{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        new_owner : felt) -> (new_owner : felt):
    # Only the current owner can transfer ownership to another account
    _only_owner()

    # Ownership cannot be transferred to the zero address, so we check
    with_attr error_message("ERC20: cannot transfer ownership to the zero address"):
        assert_not_zero(new_owner)
    end

    # Transfer the ownership of the contract
    let (previous_owner) = contract_owner.read()
    contract_owner.write(new_owner)
    OwnershipChange.emit(previous_owner, new_owner)

    # Return the new owner's address
    return (new_owner=new_owner)
end

# A function to halt normal operation of the contract. Some functions
# may still be available
@external
func pause{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    # THe contract can only be paused by the contract's owner and when not
    # already paused
    _only_owner()
    _when_not_paused()

    # Pause the contract and emit the Paused event
    paused_.write(TRUE)
    Paused.emit(TRUE)
    return ()
end

# A function to restore normal operation of the contract.
@external
func unpause{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    # THe contract can only be unpaused by the contract's owner and when the
    # contract is paused
    _only_owner()
    _when_paused()

    # Unpause the contract and emit the Paused event
    paused_.write(FALSE)
    Paused.emit(FALSE)
    return ()
end

#
# Internals
#

# Function to facititate the transfer of tokens
func _transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        sender : felt, recipient : felt, amount : Uint256):
    alloc_locals

    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: amount is not a valid Uint256"):
        uint256_check(amount)
    end

    # We cannot transfer from the zero address, so we check
    with_attr error_message("ERC20: cannot transfer from the zero address"):
        assert_not_zero(sender)
    end

    # We cannot transfer to the zero address, so we check
    with_attr error_message("ERC20: cannot transfer to the zero address"):
        assert_not_zero(recipient)
    end

    # We cannot transfer more tokens than the account hold, so we check then
    # subtract the amount of the transfer from the sender
    let (sender_balance : Uint256) = balances.read(account=sender)
    with_attr error_message("ERC20: transfer amount exceeds balance"):
        let (new_sender_balance : Uint256) = uint256_checked_sub_le(sender_balance, amount)
    end
    balances.write(sender, new_sender_balance)

    # Add the tokens to be transferred to recipient's balance
    let (recipient_balance : Uint256) = balances.read(account=recipient)
    # overflow is not possible because sum is guaranteed by mint to be less than total supply
    let (new_recipient_balance : Uint256) = uint256_checked_add(recipient_balance, amount)
    balances.write(recipient, new_recipient_balance)
    Transfer.emit(sender, recipient, amount)

    return ()
end

# A function for the mint of tokens. This function is used by the constructor
# to mint the inial supply and thereafter is called only by the external mint
# function to mint additional tokens
func _mint{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, amount : Uint256):
    # Verify that the given value is a valid integer
    with_attr error_message("ERC20: amount is not a valid Uint256"):
        uint256_check(amount)
    end

    # The zero address cannot be minted tokens, so we check
    with_attr error_message("ERC20: cannot mint to the zero address"):
        assert_not_zero(recipient)
    end

    # Check that the new suuply is within bounds and add to the amount
    # of the mint to the current supply
    let (supply : Uint256) = total_supply.read()
    with_attr error_message("ERCO20: mint overflow"):
        let (new_supply : Uint256) = uint256_checked_add(supply, amount)
    end
    total_supply.write(new_supply)

    # Update the recipient's balance with the amount of the mint
    let (balance : Uint256) = balances.read(account=recipient)
    # overflow is not possible because sum is guaranteed to be less than total supply
    # which we check for overflow below
    let (new_balance : Uint256) = uint256_checked_add(balance, amount)
    balances.write(recipient, new_balance)
    Transfer.emit(0, recipient, amount)
    return ()
end

# Function to ensure certain transactions can only be done by the contract's
# owner. This function should be called by another function that should be
# restricted to use by the contract owner. It should be called before any
# operations that will modify the state of the contract.
func _only_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    # Check that the owner and the caller are the same account
    let (owner) = contract_owner.read()
    let (caller) = get_caller_address()
    with_attr error_message("Ownable: caller is not the owner"):
        assert owner = caller
    end

    return ()
end

# Function to check that the contract is paused. Used in functions that should
# only be called when the contract is paused
func _when_paused{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    let (is_paused) = paused_.read()
    with_attr error_message("Pausable: contract is not paused"):
        assert is_paused = TRUE
    end
    return ()
end

# Function to check that the contract is not paused. Used in functions that
# should only be called when the contract is not paused
func _when_not_paused{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    let (is_paused) = paused_.read()
    with_attr error_message("Pausable: contract is paused"):
        assert is_paused = FALSE
    end
    return ()
end
