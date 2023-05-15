// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useAppsBackend } from '@mysten/core';
import {
    Info12,
    WalletActionBuy24,
    WalletActionSend24,
    Swap16,
} from '@mysten/icons';
import { SUI_TYPE_ARG, Coin } from '@mysten/sui.js';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { useOnrampProviders } from '../onramp/useOnrampProviders';
import { CoinActivitiesCard } from './CoinActivityCard';
import { TokenIconLink } from './TokenIconLink';
import CoinBalance from './coin-balance';
import { useActiveAddress } from '_app/hooks/useActiveAddress';
import { LargeButton } from '_app/shared/LargeButton';
import { Text } from '_app/shared/text';
import { CoinItem } from '_components/active-coins-card/CoinItem';
import Alert from '_components/alert';
import Loading from '_components/loading';
import { useAppSelector, useGetAllBalances, useGetCoinBalance } from '_hooks';
import { API_ENV } from '_src/shared/api-env';
import { AccountSelector } from '_src/ui/app/components/AccountSelector';
import { useLedgerNotification } from '_src/ui/app/hooks/useLedgerNotification';
import PageTitle from '_src/ui/app/shared/PageTitle';
import FaucetRequestButton from '_src/ui/app/shared/faucet/FaucetRequestButton';
import { IndentedTitle } from '_src/ui/app/shared/indented-title';

type TokenDetailsProps = {
    coinType?: string;
};

function MyTokens() {
    const accountAddress = useActiveAddress();
    const {
        data: balance,
        isLoading,
        isFetched,
    } = useGetAllBalances(accountAddress);

    const noSuiToken = !balance?.find(
        ({ coinType }) => coinType === SUI_TYPE_ARG
    );

    // Avoid perpetual loading state when fetching and retry keeps failing; add isFetched check.
    const isFirstTimeLoading = isLoading && !isFetched;

    return (
        <Loading loading={isFirstTimeLoading}>
            {balance?.length ? (
                <div className="flex flex-1 justify-start flex-col w-full mt-6">
                    <IndentedTitle title="My Coins">
                        <div className="flex flex-col w-full justify-center divide-y divide-solid divide-steel/20 divide-x-0 px-1 mb-10">
                            {balance.map(({ coinType, totalBalance }) => (
                                <Link
                                    to={`/send?type=${encodeURIComponent(
                                        coinType
                                    )}`}
                                    key={coinType}
                                    className="py-3 no-underline items-center w-full"
                                >
                                    <CoinItem
                                        coinType={coinType}
                                        balance={BigInt(totalBalance)}
                                    />
                                </Link>
                            ))}
                        </div>
                    </IndentedTitle>
                </div>
            ) : null}
            {noSuiToken ? (
                <div className="flex flex-col flex-nowrap justify-center items-center gap-2 text-center mt-6 px-2.5">
                    <FaucetRequestButton />
                    <Text variant="pBodySmall" color="gray-80" weight="normal">
                        To conduct transactions on the Sui network, you need SUI
                        in your wallet.
                    </Text>
                </div>
            ) : null}
        </Loading>
    );
}

function TokenDetails({ coinType }: TokenDetailsProps) {
    const activeCoinType = coinType || SUI_TYPE_ARG;
    const accountAddress = useActiveAddress();
    const {
        data: coinBalance,
        isError,
        isLoading,
        isFetched,
    } = useGetCoinBalance(activeCoinType, accountAddress);
    const { apiEnv } = useAppSelector((state) => state.app);
    const request = useAppsBackend();
    const { data } = useQuery({
        queryKey: ['apps-backend', 'monitor-network'],
        queryFn: () =>
            request<{ degraded: boolean }>('monitor-network', {
                project: 'WALLET',
            }),
        // Keep cached for 2 minutes:
        staleTime: 2 * 60 * 1000,
        retry: false,
        enabled: apiEnv === API_ENV.mainnet,
    });

    useLedgerNotification();

    const { providers } = useOnrampProviders();

    const tokenBalance = coinBalance?.totalBalance || BigInt(0);

    const coinSymbol = useMemo(
        () => Coin.getCoinSymbol(activeCoinType),
        [activeCoinType]
    );
    // Avoid perpetual loading state when fetching and retry keeps failing add isFetched check
    const isFirstTimeLoading = isLoading && !isFetched;

    return (
        <>
            {apiEnv === API_ENV.mainnet && data?.degraded && (
                <div className="rounded-2xl bg-warning-light border border-solid border-warning-dark/20 text-warning-dark flex items-center py-2 px-3 mb-4">
                    <Info12 className="shrink-0" />
                    <div className="ml-2">
                        <Text variant="pBodySmall" weight="medium">
                            We're sorry that the app is running slower than
                            usual. We're working to fix the issue and appreciate
                            your patience.
                        </Text>
                    </div>
                </div>
            )}

            <Loading loading={isFirstTimeLoading}>
                {coinType && <PageTitle title={coinSymbol} back="/tokens" />}

                <div
                    className="flex flex-col h-full flex-1 flex-grow items-center"
                    data-testid="coin-page"
                >
                    {!coinType && <AccountSelector />}
                    <div className="mt-1.5">
                        <CoinBalance
                            balance={BigInt(tokenBalance)}
                            type={activeCoinType}
                            mode="standalone"
                        />
                    </div>
                    {isError ? (
                        <Alert>
                            <div>
                                <strong>Error updating balance</strong>
                            </div>
                        </Alert>
                    ) : null}
                    <div className="flex flex-nowrap gap-3 justify-center w-full mt-5">
                        <LargeButton
                            center
                            to="/onramp"
                            disabled={
                                (coinType && coinType !== SUI_TYPE_ARG) ||
                                !providers?.length
                            }
                            top={<WalletActionBuy24 />}
                        >
                            Buy
                        </LargeButton>

                        <LargeButton
                            center
                            to={`/send${
                                coinBalance?.coinType
                                    ? `?${new URLSearchParams({
                                          type: coinBalance.coinType,
                                      }).toString()}`
                                    : ''
                            }`}
                            disabled={!tokenBalance}
                            top={<WalletActionSend24 />}
                        >
                            Send
                        </LargeButton>

                        <LargeButton center to="/" disabled top={<Swap16 />}>
                            Swap
                        </LargeButton>
                    </div>

                    {activeCoinType === SUI_TYPE_ARG && accountAddress ? (
                        <div className="mt-6 flex justify-start gap-2 flex-col w-full">
                            <IndentedTitle title="SUI Stake">
                                <TokenIconLink
                                    accountAddress={accountAddress}
                                />
                            </IndentedTitle>
                        </div>
                    ) : null}

                    {!coinType ? (
                        <MyTokens />
                    ) : (
                        <div className="mt-6 flex-1 justify-start gap-2 flex-col w-full">
                            <Text
                                variant="caption"
                                color="steel"
                                weight="semibold"
                            >
                                {coinSymbol} activity
                            </Text>
                            <div className="flex flex-col flex-nowrap flex-1">
                                <CoinActivitiesCard coinType={activeCoinType} />
                            </div>
                        </div>
                    )}
                </div>
            </Loading>
        </>
    );
}

export default TokenDetails;
