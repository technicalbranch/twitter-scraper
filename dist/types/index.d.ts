import { Cookie } from 'tough-cookie';
import fetch from 'cross-fetch';

type FetchParameters = [input: RequestInfo | URL, init?: RequestInit];
interface FetchTransformOptions {
    /**
     * Transforms the request options before a request is made. This executes after all of the default
     * parameters have been configured, and is stateless. It is safe to return new request options
     * objects.
     * @param args The request options.
     * @returns The transformed request options.
     */
    request: (...args: FetchParameters) => FetchParameters | Promise<FetchParameters>;
    /**
     * Transforms the response after a request completes. This executes immediately after the request
     * completes, and is stateless. It is safe to return a new response object.
     * @param response The response object.
     * @returns The transformed response object.
     */
    response: (response: Response) => Response | Promise<Response>;
}

interface LegacyUserRaw {
    created_at?: string;
    description?: string;
    entities?: {
        url?: {
            urls?: {
                expanded_url?: string;
            }[];
        };
    };
    favourites_count?: number;
    followers_count?: number;
    friends_count?: number;
    media_count?: number;
    statuses_count?: number;
    id_str?: string;
    listed_count?: number;
    name?: string;
    location: string;
    geo_enabled?: boolean;
    pinned_tweet_ids_str?: string[];
    profile_background_color?: string;
    profile_banner_url?: string;
    profile_image_url_https?: string;
    protected?: boolean;
    screen_name?: string;
    verified?: boolean;
    has_custom_timelines?: boolean;
    has_extended_profile?: boolean;
    url?: string;
    can_dm?: boolean;
}
/**
 * A parsed profile object.
 */
interface Profile {
    avatar?: string;
    banner?: string;
    biography?: string;
    birthday?: string;
    followersCount?: number;
    followingCount?: number;
    friendsCount?: number;
    mediaCount?: number;
    statusesCount?: number;
    isPrivate?: boolean;
    isVerified?: boolean;
    isBlueVerified?: boolean;
    joined?: Date;
    likesCount?: number;
    listedCount?: number;
    location: string;
    name?: string;
    pinnedTweetIds?: string[];
    tweetsCount?: number;
    url?: string;
    userId?: string;
    username?: string;
    website?: string;
    canDm?: boolean;
}

interface Mention {
    id: string;
    username?: string;
    name?: string;
}
interface Photo {
    id: string;
    url: string;
    alt_text: string | undefined;
}
interface Video {
    id: string;
    preview: string;
    url?: string;
}
interface PlaceRaw {
    id?: string;
    place_type?: string;
    name?: string;
    full_name?: string;
    country_code?: string;
    country?: string;
    bounding_box?: {
        type?: string;
        coordinates?: number[][][];
    };
}
/**
 * A parsed Tweet object.
 */
interface Tweet {
    __raw_UNSTABLE?: LegacyTweetRaw;
    bookmarkCount?: number;
    conversationId?: string;
    hashtags: string[];
    html?: string;
    id?: string;
    inReplyToStatus?: Tweet;
    inReplyToStatusId?: string;
    isEdited?: boolean;
    versions?: string[];
    isQuoted?: boolean;
    isPin?: boolean;
    isReply?: boolean;
    isRetweet?: boolean;
    isSelfThread?: boolean;
    likes?: number;
    name?: string;
    mentions: Mention[];
    permanentUrl?: string;
    photos: Photo[];
    place?: PlaceRaw;
    quotedStatus?: Tweet;
    quotedStatusId?: string;
    replies?: number;
    retweets?: number;
    retweetedStatus?: Tweet;
    retweetedStatusId?: string;
    text?: string;
    thread: Tweet[];
    timeParsed?: Date;
    timestamp?: number;
    urls: string[];
    userId?: string;
    username?: string;
    videos: Video[];
    views?: number;
    sensitiveContent?: boolean;
}
type TweetQuery = Partial<Tweet> | ((tweet: Tweet) => boolean | Promise<boolean>);

interface Hashtag {
    text?: string;
}
interface TimelineUserMentionBasicRaw {
    id_str?: string;
    name?: string;
    screen_name?: string;
}
interface TimelineMediaBasicRaw {
    media_url_https?: string;
    type?: string;
    url?: string;
}
interface TimelineUrlBasicRaw {
    expanded_url?: string;
    url?: string;
}
interface ExtSensitiveMediaWarningRaw {
    adult_content?: boolean;
    graphic_violence?: boolean;
    other?: boolean;
}
interface VideoVariant {
    bitrate?: number;
    url?: string;
}
interface VideoInfo {
    variants?: VideoVariant[];
}
interface TimelineMediaExtendedRaw {
    id_str?: string;
    media_url_https?: string;
    ext_sensitive_media_warning?: ExtSensitiveMediaWarningRaw;
    type?: string;
    url?: string;
    video_info?: VideoInfo;
    ext_alt_text: string | undefined;
}
interface TimelineResultRaw {
    rest_id?: string;
    __typename?: string;
    core?: {
        user_results?: {
            result?: {
                is_blue_verified?: boolean;
                legacy?: LegacyUserRaw;
            };
        };
    };
    views?: {
        count?: string;
    };
    note_tweet?: {
        note_tweet_results?: {
            result?: {
                text?: string;
            };
        };
    };
    quoted_status_result?: {
        result?: TimelineResultRaw;
    };
    legacy?: LegacyTweetRaw;
    tweet?: TimelineResultRaw;
}
interface LegacyTweetRaw {
    bookmark_count?: number;
    conversation_id_str?: string;
    created_at?: string;
    favorite_count?: number;
    full_text?: string;
    entities?: {
        hashtags?: Hashtag[];
        media?: TimelineMediaBasicRaw[];
        urls?: TimelineUrlBasicRaw[];
        user_mentions?: TimelineUserMentionBasicRaw[];
    };
    extended_entities?: {
        media?: TimelineMediaExtendedRaw[];
    };
    id_str?: string;
    in_reply_to_status_id_str?: string;
    place?: PlaceRaw;
    reply_count?: number;
    retweet_count?: number;
    retweeted_status_id_str?: string;
    retweeted_status_result?: {
        result?: TimelineResultRaw;
    };
    quoted_status_id_str?: string;
    time?: string;
    user_id_str?: string;
    ext_views?: {
        state?: string;
        count?: string;
    };
}
/**
 * A paginated tweets API response. The `next` field can be used to fetch the next page of results,
 * and the `previous` can be used to fetch the previous results (or results created after the
 * inital request)
 */
interface QueryTweetsResponse {
    tweets: Tweet[];
    next?: string;
    previous?: string;
}
/**
 * A paginated profiles API response. The `next` field can be used to fetch the next page of results.
 */
interface QueryProfilesResponse {
    profiles: Profile[];
    next?: string;
    previous?: string;
}

/**
 * The categories that can be used in Twitter searches.
 */
declare enum SearchMode {
    Top = 0,
    Latest = 1,
    Photos = 2,
    Videos = 3,
    Users = 4
}

interface ScraperOptions {
    /**
     * An alternative fetch function to use instead of the default fetch function. This may be useful
     * in nonstandard runtime environments, such as edge workers.
     */
    fetch: typeof fetch;
    /**
     * Additional options that control how requests and responses are processed. This can be used to
     * proxy requests through other hosts, for example.
     */
    transform: Partial<FetchTransformOptions>;
}
/**
 * An interface to Twitter's undocumented API.
 * - Reusing Scraper objects is recommended to minimize the time spent authenticating unnecessarily.
 */
declare class Scraper {
    private readonly options?;
    private auth;
    private authTrends;
    private token;
    /**
     * Creates a new Scraper object.
     * - Scrapers maintain their own guest tokens for Twitter's internal API.
     * - Reusing Scraper objects is recommended to minimize the time spent authenticating unnecessarily.
     */
    constructor(options?: Partial<ScraperOptions> | undefined);
    /**
     * Fetches a Twitter profile.
     * @param username The Twitter username of the profile to fetch, without an `@` at the beginning.
     * @returns The requested {@link Profile}.
     */
    getProfile(username: string): Promise<Profile>;
    /**
     * Fetches the user ID corresponding to the provided screen name.
     * @param screenName The Twitter screen name of the profile to fetch.
     * @returns The ID of the corresponding account.
     */
    getUserIdByScreenName(screenName: string): Promise<string>;
    /**
     * Fetches tweets from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxTweets The maximum number of tweets to return.
     * @param includeReplies Whether or not replies should be included in the response.
     * @param searchMode The category filter to apply to the search. Defaults to `Top`.
     * @returns An {@link AsyncGenerator} of tweets matching the provided filters.
     */
    searchTweets(query: string, maxTweets: number, searchMode?: SearchMode): AsyncGenerator<Tweet, string | undefined>;
    /**
     * Fetches profiles from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of tweets matching the provided filter(s).
     */
    searchProfiles(query: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetches tweets from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxTweets The maximum number of tweets to return.
     * @param includeReplies Whether or not replies should be included in the response.
     * @param searchMode The category filter to apply to the search. Defaults to `Top`.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchSearchTweets(query: string, maxTweets: number, searchMode: SearchMode, cursor?: string): Promise<QueryTweetsResponse>;
    /**
     * Fetches profiles from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchSearchProfiles(query: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches list tweets from Twitter.
     * @param listId The list id
     * @param maxTweets The maximum number of tweets to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchListTweets(listId: string, maxTweets: number, cursor?: string): Promise<QueryTweetsResponse>;
    /**
     * Fetch the profiles a user is following
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of following profiles for the provided user.
     */
    getFollowing(userId: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetch the profiles that follow a user
     * @param userId The user whose followers should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of profiles following the provided user.
     */
    getFollowers(userId: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetches following profiles from Twitter.
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchProfileFollowing(userId: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches profile followers from Twitter.
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchProfileFollowers(userId: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches the current trends from Twitter.
     * @returns The current list of trends.
     */
    getTrends(): Promise<string[]>;
    /**
     * Fetches tweets from a Twitter user.
     * @param user The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweets(user: string, maxTweets?: number, cursor?: string): AsyncGenerator<Tweet, string | undefined>;
    /**
     * Fetches liked tweets from a Twitter user. Requires authentication.
     * @param user The user whose likes should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of liked tweets from the provided user.
     */
    getLikedTweets(user: string, maxTweets?: number): AsyncGenerator<Tweet>;
    /**
     * Fetches tweets from a Twitter user using their ID.
     * @param userId The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsByUserId(userId: string, maxTweets?: number): AsyncGenerator<Tweet, string | undefined>;
    /**
     * Fetches tweets and replies from a Twitter user.
     * @param user The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsAndReplies(user: string, maxTweets?: number): AsyncGenerator<Tweet>;
    /**
     * Fetches tweets and replies from a Twitter user using their ID.
     * @param userId The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsAndRepliesByUserId(userId: string, maxTweets?: number): AsyncGenerator<Tweet, string | undefined>;
    /**
     * Fetches the first tweet matching the given query.
     *
     * Example:
     * ```js
     * const timeline = scraper.getTweets('user', 200);
     * const retweet = await scraper.getTweetWhere(timeline, { isRetweet: true });
     * ```
     * @param tweets The {@link AsyncIterable} of tweets to search through.
     * @param query A query to test **all** tweets against. This may be either an
     * object of key/value pairs or a predicate. If this query is an object, all
     * key/value pairs must match a {@link Tweet} for it to be returned. If this query
     * is a predicate, it must resolve to `true` for a {@link Tweet} to be returned.
     * - All keys are optional.
     * - If specified, the key must be implemented by that of {@link Tweet}.
     */
    getTweetWhere(tweets: AsyncIterable<Tweet>, query: TweetQuery): Promise<Tweet | null>;
    /**
     * Fetches all tweets matching the given query.
     *
     * Example:
     * ```js
     * const timeline = scraper.getTweets('user', 200);
     * const retweets = await scraper.getTweetsWhere(timeline, { isRetweet: true });
     * ```
     * @param tweets The {@link AsyncIterable} of tweets to search through.
     * @param query A query to test **all** tweets against. This may be either an
     * object of key/value pairs or a predicate. If this query is an object, all
     * key/value pairs must match a {@link Tweet} for it to be returned. If this query
     * is a predicate, it must resolve to `true` for a {@link Tweet} to be returned.
     * - All keys are optional.
     * - If specified, the key must be implemented by that of {@link Tweet}.
     */
    getTweetsWhere(tweets: AsyncIterable<Tweet>, query: TweetQuery): Promise<Tweet[]>;
    /**
     * Fetches the most recent tweet from a Twitter user.
     * @param user The user whose latest tweet should be returned.
     * @param includeRetweets Whether or not to include retweets. Defaults to `false`.
     * @returns The {@link Tweet} object or `null`/`undefined` if it couldn't be fetched.
     */
    getLatestTweet(user: string, includeRetweets?: boolean, max?: number): Promise<Tweet | string | null | void>;
    /**
     * Fetches a single tweet.
     * @param id The ID of the tweet to fetch.
     * @returns The {@link Tweet} object, or `null` if it couldn't be fetched.
     */
    getTweet(id: string): Promise<Tweet | null>;
    /**
     * Returns if the scraper has a guest token. The token may not be valid.
     * @returns `true` if the scraper has a guest token; otherwise `false`.
     */
    hasGuestToken(): boolean;
    /**
     * Returns if the scraper is logged in as a real user.
     * @returns `true` if the scraper is logged in with a real user account; otherwise `false`.
     */
    isLoggedIn(): Promise<boolean>;
    /**
     * Login to Twitter as a real Twitter account. This enables running
     * searches.
     * @param username The username of the Twitter account to login with.
     * @param password The password of the Twitter account to login with.
     * @param email The email to log in with, if you have email confirmation enabled.
     * @param twoFactorSecret The secret to generate two factor authentication tokens with, if you have two factor authentication enabled.
     */
    login(username: string, password: string, email?: string, twoFactorSecret?: string): Promise<void>;
    /**
     * Log out of Twitter.
     */
    logout(): Promise<void>;
    /**
     * Retrieves all cookies for the current session.
     * @returns All cookies for the current session.
     */
    getCookies(): Promise<Cookie[]>;
    /**
     * Set cookies for the current session.
     * @param cookies The cookies to set for the current session.
     */
    setCookies(cookies: (string | Cookie)[]): Promise<void>;
    /**
     * Clear all cookies for the current session.
     */
    clearCookies(): Promise<void>;
    /**
     * Sets the optional cookie to be used in requests.
     * @param _cookie The cookie to be used in requests.
     * @deprecated This function no longer represents any part of Twitter's auth flow.
     * @returns This scraper instance.
     */
    withCookie(_cookie: string): Scraper;
    /**
     * Sets the optional CSRF token to be used in requests.
     * @param _token The CSRF token to be used in requests.
     * @deprecated This function no longer represents any part of Twitter's auth flow.
     * @returns This scraper instance.
     */
    withXCsrfToken(_token: string): Scraper;
    private getAuthOptions;
    private handleResponse;
}

export { type Mention, type Photo, type PlaceRaw, type Profile, type QueryProfilesResponse, type QueryTweetsResponse, Scraper, SearchMode, type Tweet, type Video };
