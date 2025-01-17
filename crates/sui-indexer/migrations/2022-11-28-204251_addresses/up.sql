CREATE TABLE addresses
(
    account_address       address       PRIMARY KEY,
    first_appearance_tx   base58digest  NOT NULL,
    first_appearance_time BIGINT        NOT NULL,
    last_appearance_tx    base58digest  NOT NULL,
    last_appearance_time  BIGINT        NOT NULL
);

CREATE TABLE active_addresses
(
    account_address       address       PRIMARY KEY,
    first_appearance_tx   base58digest  NOT NULL,
    first_appearance_time BIGINT        NOT NULL,
    last_appearance_tx    base58digest  NOT NULL,
    last_appearance_time  BIGINT        NOT NULL
);
