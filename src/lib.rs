#![deny(clippy::all)]
#![allow(unexpected_cfgs, deprecated, unused)]
use {
    core::mem::size_of, solana_program::{
        account_info::{next_account_info, AccountInfo}, entrypoint::{ProgramResult, entrypoint}, msg, program::{invoke, invoke_signed}, program_error::ProgramError, pubkey::Pubkey, system_instruction, sysvar::{rent::Rent, Sysvar},
        system_program::ID, instruction::{AccountMeta, Instruction}, sysvar::clock::Clock
    }, std::str::FromStr, core::fmt::Write
};

const SEED_CONFIG: &[u8] = b"config";
const SEED_USER: &[u8] = b"user";
const ADMIN_PUBKEY: &str = "FZqVN52PFaJLebFGZe5ZXixYfoDy98stN5oddqVHz2rW";
const USER_SPACE: usize = 32 + 8*3;
const CONFIG_SPACE: usize = 32 + 8*4;
const POST_TAG: u8 = 6;
const MEMO_MAGIC: &[u8] = b"F4HPOST";
const MEMO_VERSION: u8 = 2;
const MEMO_PID_STR: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// This program in its main principle assures that all posts and likes are reflected on the blockchain, which serves as a trustworthy way to share content with the community.
/// FLOCK4H 2025

/// Config account
/// Authority is the admin account that can update the config
/// Post fee is the fee for posting a post, serves as an anti-spam measure
/// Like fee is the fee for liking a post, serves as an anti-spam measure
/// Post fee author cut is the percentage of the post fee that goes to the author
/// Like fee author cut is the percentage of the like fee that goes to the author
#[repr(C)]
pub struct Config {
    pub authority: Pubkey,
    pub post_fee: u64,
    pub like_fee: u64,
    pub post_fee_author_cut: u64, // 33%
    pub like_fee_author_cut: u64, // 33%
}

/// User account
/// Holds balance, username, and data of the account
#[repr(C)]
pub struct UserAccount {
    pub username: [u8; 32],
    pub posts_created: u64, // post_seq
    pub likes_received: u64,
    pub likes_given: u64,
}

/// Post instruction struct
/// Chunk's data is stored in the memo of the transaction.
#[repr(C)]
pub struct PostInstruction {
    pub post_id: (Pubkey, u64),
    pub author: Pubkey,
    pub is_head: bool,
    pub chunk_id: u64,
    pub chunk_total: u64,
    pub timestamp: u64,
}

/// Like instruction struct
#[repr(C)]
pub struct LikeInstruction {
    pub post_id: (Pubkey, u64),
    pub liker: Pubkey,
    pub timestamp: u64,
}

#[inline(always)]
fn require(cond: bool, e: ProgramError) -> ProgramResult {
    if cond { Ok(()) } else { Err(e) }
}

#[inline(always)]
fn parse_amount(ix: &[u8]) -> Result<u64, ProgramError> {
    if ix.len() != 1 + 8 { return Err(ProgramError::InvalidInstructionData); }
    Ok(u64::from_le_bytes(ix[1..9].try_into().unwrap()))
}

#[inline(always)]
fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

fn parse_config(data: &[u8]) -> Result<Config, ProgramError> {
    if data.len() != 1 + 32 + 8*4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let body = &data[1..]; // <— skip tag
    let mut o: usize = 0;
    let take = |n: usize, o: &mut usize| { let s = &body[*o..*o+n]; *o += n; s };

    let authority = Pubkey::new_from_array(take(32, &mut o).try_into().unwrap());
    let u64le = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    Ok(Config {
        authority,
        post_fee: u64le(take(8, &mut o)),
        like_fee: u64le(take(8, &mut o)),
        post_fee_author_cut: u64le(take(8, &mut o)),
        like_fee_author_cut: u64le(take(8, &mut o)),
    })
}

fn parse_user(ix: &[u8]) -> Result<UserAccount, ProgramError> {
    if ix.len() != 1 + 32 + 8*3 { return Err(ProgramError::InvalidInstructionData); }
    let b = &ix[1..];
    let mut o: usize = 0;
    let mut username = [0u8; 32];
    username.copy_from_slice(&b[o..o+32]); o += 32;
    let u64le = |x: &[u8]| u64::from_le_bytes(x.try_into().unwrap());
    let posts_created = u64le(&b[o..o+8]); o += 8;
    let likes_received = u64le(&b[o..o+8]); o += 8;
    let likes_given    = u64le(&b[o..o+8]); o += 8;
    Ok(UserAccount { username, posts_created, likes_received, likes_given })
}

fn parse_post(ix: &[u8]) -> Result<(Pubkey, bool, u16, u16, &[u8]), ProgramError> {
    if ix.len() < 1 + 32 + 1 + 2 + 2 + 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut o = 1;
    let mut take = |n: usize| { let s = &ix[o..o+n]; o += n; s };

    let owner = Pubkey::new_from_array(take(32).try_into().unwrap());
    let is_head = take(1)[0] != 0;
    let chunk_id = u16::from_le_bytes(take(2).try_into().unwrap());
    let chunk_total = u16::from_le_bytes(take(2).try_into().unwrap());
    let clen = u16::from_le_bytes(take(2).try_into().unwrap()) as usize;

    if ix.len() < o + clen { return Err(ProgramError::InvalidInstructionData); }
    let content = &ix[o..o+clen];
    Ok((owner, is_head, chunk_id, chunk_total, content))
}

fn parse_like(ix: &[u8]) -> Result<((Pubkey, u64), Pubkey, u64), ProgramError> {
    if ix.len() != 1 + 32 + 8 + 32 + 8 { return Err(ProgramError::InvalidInstructionData); }
    let mut o = 1;
    let mut take = |n: usize| { let s = &ix[o..o+n]; o += n; s };
    let post_owner = Pubkey::new_from_array(take(32).try_into().unwrap());
    let post_seq   = u64::from_le_bytes(take(8).try_into().unwrap());
    let liker      = Pubkey::new_from_array(take(32).try_into().unwrap());
    let ts_client  = u64::from_le_bytes(take(8).try_into().unwrap());
    Ok(((post_owner, post_seq), liker, ts_client))
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix_data: &[u8],
) -> ProgramResult {
    if ix_data.is_empty() {
        msg!("by FLOCK4H 2025");
        return Ok(());
    }

    match ix_data[0] {
        0 => init_config(program_id, accounts, ix_data),
        1 => update_config(program_id, accounts, ix_data),
        2 => init_user(program_id, accounts, ix_data),
        3 => update_user(program_id, accounts, ix_data),
        4 => user_deposit(program_id, accounts, ix_data),
        5 => user_withdraw(program_id, accounts, ix_data),
        6 => post(program_id, accounts, ix_data),
        7 => like(program_id, accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn init_config(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let cfg = parse_config(data)?;
    let admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();

    let mut it = accounts.iter();
    let payer   = next_account_info(&mut it)?; // must be admin
    let cfg_ai  = next_account_info(&mut it)?; // PDA
    let system  = next_account_info(&mut it)?;

    require(payer.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*payer.key == admin, ProgramError::InvalidSeeds)?;
    require(*system.key == ID, ProgramError::InvalidAccountData)?;

    let (cfg_pda, bump) = Pubkey::find_program_address(&[SEED_CONFIG], program_id);
    require(*cfg_ai.key == cfg_pda, ProgramError::InvalidSeeds)?;
    require(cfg_ai.lamports() == 0, ProgramError::AccountAlreadyInitialized)?;

    let space = CONFIG_SPACE;
    let lamports = Rent::get()?.minimum_balance(space);
    let ix = system_instruction::create_account(
        payer.key, &cfg_pda, lamports, space as u64, program_id,
    );
    invoke_signed(
        &ix,
        &[payer.clone(), cfg_ai.clone(), system.clone()],
        &[&[SEED_CONFIG, &[bump]]],
    )?;

    let mut d = cfg_ai.try_borrow_mut_data()?;
    let mut _o = 0usize;
    d[_o.._o+32].copy_from_slice(cfg.authority.as_ref()); _o += 32;
    d[_o.._o+8].copy_from_slice(&cfg.post_fee.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.like_fee.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.post_fee_author_cut.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.like_fee_author_cut.to_le_bytes()); _o += 8;

    msg!("Config initialized: authority={} post_fee={} like_fee={}",
        cfg.authority, cfg.post_fee, cfg.like_fee);
    Ok(())
}

fn update_config(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let cfg = parse_config(data)?;
    let admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();

    let mut it = accounts.iter();
    let payer   = next_account_info(&mut it)?;
    let cfg_ai  = next_account_info(&mut it)?;

    require(payer.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*payer.key == admin, ProgramError::InvalidSeeds)?;

    let (cfg_pda, _bump) = Pubkey::find_program_address(&[SEED_CONFIG], program_id);
    require(*cfg_ai.key == cfg_pda, ProgramError::InvalidSeeds)?;
    
    let mut d = cfg_ai.try_borrow_mut_data()?;
    let mut _o = 0usize;
    d[_o.._o+32].copy_from_slice(cfg.authority.as_ref()); _o += 32;
    d[_o.._o+8].copy_from_slice(&cfg.post_fee.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.like_fee.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.post_fee_author_cut.to_le_bytes()); _o += 8;
    d[_o.._o+8].copy_from_slice(&cfg.like_fee_author_cut.to_le_bytes()); _o += 8;

    msg!("Config updated: authority={} post_fee={} like_fee={}",
        cfg.authority, cfg.post_fee, cfg.like_fee);
    Ok(())
}

fn init_user(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user = parse_user(data)?;
    let admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();

    let mut it = accounts.iter();
    let payer   = next_account_info(&mut it)?;  // admin, funds & signer
    let owner   = next_account_info(&mut it)?;  // the user's wallet (readonly)
    let user_ai = next_account_info(&mut it)?;  // PDA ["user", owner]
    let system  = next_account_info(&mut it)?;

    require(payer.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*payer.key == admin, ProgramError::InvalidSeeds)?;
    require(*system.key == ID, ProgramError::InvalidAccountData)?;

    let (user_pda, bump) = Pubkey::find_program_address(&[SEED_USER, owner.key.as_ref()], program_id);
    require(*user_ai.key == user_pda, ProgramError::InvalidSeeds)?;
    require(user_ai.lamports() == 0, ProgramError::AccountAlreadyInitialized)?;

    let lamports = Rent::get()?.minimum_balance(USER_SPACE);
    let ix = system_instruction::create_account(payer.key, &user_pda, lamports, USER_SPACE as u64, program_id);

    invoke_signed(
        &ix,
        &[payer.clone(), user_ai.clone(), system.clone()],
        &[&[SEED_USER, owner.key.as_ref(), &[bump]]],
    )?;

    let mut d = user_ai.try_borrow_mut_data()?;
    let mut o: usize = 0;
    d[o..o+32].copy_from_slice(&user.username); o += 32;
    d[o..o+8].copy_from_slice(&user.posts_created.to_le_bytes()); o += 8;
    d[o..o+8].copy_from_slice(&user.likes_received.to_le_bytes()); o += 8;
    d[o..o+8].copy_from_slice(&user.likes_given.to_le_bytes());

    msg!("User initialized for owner {}", owner.key);
    Ok(())
}

fn update_user(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user = parse_user(data)?;
    let admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();

    let mut it = accounts.iter();
    let payer   = next_account_info(&mut it)?;  // signer/admin
    let owner   = next_account_info(&mut it)?;  // the user's wallet (readonly)
    let user_ai = next_account_info(&mut it)?;  // PDA ["user"]

    require(payer.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*payer.key == admin, ProgramError::InvalidSeeds)?;

    let (user_pda, _) = Pubkey::find_program_address(&[SEED_USER, owner.key.as_ref()], program_id);
    require(*user_ai.key == user_pda, ProgramError::InvalidSeeds)?;

    let mut d = user_ai.try_borrow_mut_data()?;
    let mut o: usize = 0;
    d[o..o+32].copy_from_slice(&user.username); o += 32;
    d[o..o+8].copy_from_slice(&user.posts_created.to_le_bytes()); o += 8;
    d[o..o+8].copy_from_slice(&user.likes_received.to_le_bytes()); o += 8;
    d[o..o+8].copy_from_slice(&user.likes_given.to_le_bytes());
    msg!("User updated");
    Ok(())
}

fn user_deposit(program_id: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let amount = parse_amount(ix)?;

    let mut it = accounts.iter();
    let funder  = next_account_info(&mut it)?; // pays lamports (signer)
    let owner   = next_account_info(&mut it)?; // the user's wallet (readonly)
    let user_ai = next_account_info(&mut it)?; // PDA ["user", owner]
    let system  = next_account_info(&mut it)?;

    require(funder.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*system.key == ID, ProgramError::InvalidAccountData)?;

    let (user_pda, _) = Pubkey::find_program_address(&[SEED_USER, owner.key.as_ref()], program_id);
    require(*user_ai.key == user_pda, ProgramError::InvalidSeeds)?;

    let ix = system_instruction::transfer(funder.key, user_ai.key, amount);
    solana_program::program::invoke(&ix, &[funder.clone(), user_ai.clone(), system.clone()])?;
    msg!("Deposit: {} lamports into {}", amount, user_ai.key);
    Ok(())
}

fn user_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let amount = parse_amount(ix)?;
    let admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();

    let mut it = accounts.iter();
    let payer   = next_account_info(&mut it)?; // admin signer
    let owner   = next_account_info(&mut it)?; // destination wallet (MUST be writable)
    let user_ai = next_account_info(&mut it)?; // PDA ["user", owner] (MUST be writable)

    require(payer.is_signer, ProgramError::MissingRequiredSignature)?;
    require(*payer.key == admin, ProgramError::InvalidSeeds)?;

    let (user_pda, _bump) = Pubkey::find_program_address(&[SEED_USER, owner.key.as_ref()], program_id);
    require(*user_ai.key == user_pda, ProgramError::InvalidSeeds)?;

    let rent_min = Rent::get()?.minimum_balance(USER_SPACE);
    let cur = **user_ai.lamports.borrow();
    require(cur >= rent_min + amount, ProgramError::InsufficientFunds)?;

    **user_ai.try_borrow_mut_lamports()? -= amount;
    **owner.try_borrow_mut_lamports()?   += amount;

    msg!("Withdraw: {} lamports from {} to {}", amount, user_ai.key, owner.key);
    Ok(())
}

fn post(program_id: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let (owner, is_head, chunk_id, chunk_total, content) = parse_post(ix)?;

    let mut it = accounts.iter();
    let admin         = next_account_info(&mut it)?; // signer
    let owner_ai      = next_account_info(&mut it)?; // ro, must equal owner
    let user_ai       = next_account_info(&mut it)?; // w
    let memo_program  = next_account_info(&mut it)?; // ro

    require(admin.is_signer, ProgramError::MissingRequiredSignature)?;
    let hardcoded_admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();
    require(*admin.key == hardcoded_admin, ProgramError::InvalidSeeds)?;

    let (expect_pda, _bump) = Pubkey::find_program_address(&[SEED_USER, owner.as_ref()], program_id);
    require(*user_ai.key == expect_pda, ProgramError::InvalidSeeds)?;
    require(*owner_ai.key == owner, ProgramError::InvalidAccountData)?;

    // update counter & compute seq
    let mut d = user_ai.try_borrow_mut_data()?;
    let mut posts_created = u64::from_le_bytes(d[32..40].try_into().unwrap());
    let seq = if is_head {
        let newv = posts_created.checked_add(1).ok_or(ProgramError::InvalidAccountData)?;
        d[32..40].copy_from_slice(&newv.to_le_bytes());
        posts_created = newv;
        newv
    } else {
        posts_created
    };

    // "F4HPOST|1|<owner>|<seq>|<chunk_id>|<chunk_total>|<hex(content)>"
    let mut memo_text = format!("F4HPOST|{}|{}|{}|{}|{}|", MEMO_VERSION, owner, seq, chunk_id, chunk_total);
    push_hex(&mut memo_text, content);
    let memo_bytes = memo_text.into_bytes();

    // CPI to SPL Memo
    let memo_pid = Pubkey::from_str(MEMO_PID_STR).unwrap();
    require(*memo_program.key == memo_pid, ProgramError::IncorrectProgramId)?;
    let memo_ix = Instruction {
        program_id: memo_pid,
        accounts: vec![AccountMeta::new_readonly(*admin.key, true)], // admin as memo signer
        data: memo_bytes,
    };
    invoke(&memo_ix, &[admin.clone(), memo_program.clone()])?;

    let ts = Clock::get()?.unix_timestamp;
    msg!("POST id=({},{}) chunk={}/{} ts={}", owner, seq, chunk_id, chunk_total, ts);

    Ok(())
}

fn like(program_id: &Pubkey, accounts: &[AccountInfo], ix: &[u8]) -> ProgramResult {
    let ((post_owner, post_seq), liker, _ts_from_client) = parse_like(ix)?;

    let mut it = accounts.iter();
    let admin      = next_account_info(&mut it)?; // signer/admin
    let liker_ai   = next_account_info(&mut it)?; // ro, must equal `liker`
    let liker_pda  = next_account_info(&mut it)?; // w, PDA ["user", liker]
    let owner_ai   = next_account_info(&mut it)?; // ro, must equal `post_owner`
    let owner_pda  = next_account_info(&mut it)?; // w, PDA ["user", post_owner]

    require(admin.is_signer, ProgramError::MissingRequiredSignature)?;
    let hardcoded_admin = Pubkey::from_str(ADMIN_PUBKEY).unwrap();
    require(*admin.key == hardcoded_admin, ProgramError::InvalidSeeds)?;

    let (expect_liker_pda, _) = Pubkey::find_program_address(&[SEED_USER, liker.as_ref()], program_id);
    require(*liker_ai.key == liker, ProgramError::InvalidAccountData)?;
    require(*liker_pda.key == expect_liker_pda, ProgramError::InvalidSeeds)?;

    let (expect_owner_pda, _) = Pubkey::find_program_address(&[SEED_USER, post_owner.as_ref()], program_id);
    require(*owner_ai.key == post_owner, ProgramError::InvalidAccountData)?;
    require(*owner_pda.key == expect_owner_pda, ProgramError::InvalidSeeds)?;

    // bump liker.likes_given  (bytes 48..56)
    {
        let mut d = liker_pda.try_borrow_mut_data()?;
        let mut v = u64::from_le_bytes(d[48..56].try_into().unwrap());
        v = v.checked_add(1).ok_or(ProgramError::InvalidAccountData)?;
        d[48..56].copy_from_slice(&v.to_le_bytes());
    }

    // also bump post_owner.likes_received (bytes 40..48)
    {
        let mut d = owner_pda.try_borrow_mut_data()?;
        let mut v = u64::from_le_bytes(d[40..48].try_into().unwrap());
        v = v.checked_add(1).ok_or(ProgramError::InvalidAccountData)?;
        d[40..48].copy_from_slice(&v.to_le_bytes());
    }

    let ts = Clock::get()?.unix_timestamp as u64; // trust chain time, not client
    msg!("LIKE post=({}, {}) by={} ts={}", post_owner, post_seq, liker, ts);
    Ok(())
}