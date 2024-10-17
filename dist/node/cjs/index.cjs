'use strict';

var toughCookie = require('tough-cookie');
var setCookie = require('set-cookie-parser');
var headersPolyfill = require('headers-polyfill');
var fetch = require('cross-fetch');
var typebox = require('@sinclair/typebox');
var value = require('@sinclair/typebox/value');
var OTPAuth = require('otpauth');
var stringify = require('json-stable-stringify');
var tls = require('node:tls');
var node_crypto = require('node:crypto');

function _interopNamespaceDefault(e) {
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var OTPAuth__namespace = /*#__PURE__*/_interopNamespaceDefault(OTPAuth);

class ApiError extends Error {
  constructor(response, data, message) {
    super(message);
    this.response = response;
    this.data = data;
  }
  static async fromResponse(response) {
    let data = void 0;
    try {
      data = await response.json();
    } catch {
      try {
        data = await response.text();
      } catch {
      }
    }
    return new ApiError(response, data, `Response status: ${response.status}`);
  }
}

class Platform {
  async randomizeCiphers() {
    const platform = await Platform.importPlatform();
    await platform?.randomizeCiphers();
  }
  static async importPlatform() {
    {
      const { platform } = await Promise.resolve().then(function () { return index; });
      return platform;
    }
  }
}

async function updateCookieJar(cookieJar, headers) {
  const setCookieHeader = headers.get("set-cookie");
  if (setCookieHeader) {
    const cookies = setCookie.splitCookiesString(setCookieHeader);
    for (const cookie of cookies.map((c) => toughCookie.Cookie.parse(c))) {
      if (!cookie) continue;
      await cookieJar.setCookie(
        cookie,
        `${cookie.secure ? "https" : "http"}://${cookie.domain}${cookie.path}`
      );
    }
  } else if (typeof document !== "undefined") {
    for (const cookie of document.cookie.split(";")) {
      const hardCookie = toughCookie.Cookie.parse(cookie);
      if (hardCookie) {
        await cookieJar.setCookie(hardCookie, document.location.toString());
      }
    }
  }
}

const bearerToken = "AAAAAAAAAAAAAAAAAAAAAFQODgEAAAAAVHTp76lzh3rFzcHbmHVvQxYYpTw%3DckAlMINMjmCwxUcaXbAN4XqJVdgMJaHqNOFgPMK0zN1qLqLQCF";
async function requestApi(url, auth, method = "GET", platform = new Platform()) {
  const headers = new headersPolyfill.Headers();
  await auth.installTo(headers, url);
  await platform.randomizeCiphers();
  let res;
  do {
    try {
      res = await auth.fetch(url, {
        method,
        headers,
        credentials: "include"
      });
    } catch (err) {
      if (!(err instanceof Error)) {
        throw err;
      }
      return {
        success: false,
        err: new Error("Failed to perform request.")
      };
    }
    await updateCookieJar(auth.cookieJar(), res.headers);
    if (res.status === 429) {
      const xRateLimitRemaining = res.headers.get("x-rate-limit-remaining");
      const xRateLimitReset = res.headers.get("x-rate-limit-reset");
      if (xRateLimitRemaining == "0" && xRateLimitReset) {
        const currentTime = (/* @__PURE__ */ new Date()).valueOf() / 1e3;
        const timeDeltaMs = 1e3 * (parseInt(xRateLimitReset) - currentTime);
        await new Promise((resolve) => setTimeout(resolve, timeDeltaMs));
      }
    }
  } while (res.status === 429);
  if (!res.ok) {
    return {
      success: false,
      err: await ApiError.fromResponse(res)
    };
  }
  const value = await res.json();
  if (res.headers.get("x-rate-limit-incoming") == "0") {
    auth.deleteToken();
    return { success: true, value };
  } else {
    return { success: true, value };
  }
}
function addApiFeatures(o) {
  return {
    ...o,
    rweb_lists_timeline_redesign_enabled: true,
    responsive_web_graphql_exclude_directive_enabled: true,
    verified_phone_label_enabled: false,
    creator_subscriptions_tweet_preview_api_enabled: true,
    responsive_web_graphql_timeline_navigation_enabled: true,
    responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
    tweetypie_unmention_optimization_enabled: true,
    responsive_web_edit_tweet_api_enabled: true,
    graphql_is_translatable_rweb_tweet_is_translatable_enabled: true,
    view_counts_everywhere_api_enabled: true,
    longform_notetweets_consumption_enabled: true,
    tweet_awards_web_tipping_enabled: false,
    freedom_of_speech_not_reach_fetch_enabled: true,
    standardized_nudges_misinfo: true,
    longform_notetweets_rich_text_read_enabled: true,
    responsive_web_enhance_cards_enabled: false,
    subscriptions_verification_info_enabled: true,
    subscriptions_verification_info_reason_enabled: true,
    subscriptions_verification_info_verified_since_enabled: true,
    super_follow_badge_privacy_enabled: false,
    super_follow_exclusive_tweet_notifications_enabled: false,
    super_follow_tweet_api_enabled: false,
    super_follow_user_api_enabled: false,
    android_graphql_skip_api_media_color_palette: false,
    creator_subscriptions_subscription_count_enabled: false,
    blue_business_profile_image_shape_enabled: false,
    unified_cards_ad_metadata_container_dynamic_card_content_query_enabled: false
  };
}
function addApiParams(params, includeTweetReplies) {
  params.set("include_profile_interstitial_type", "1");
  params.set("include_blocking", "1");
  params.set("include_blocked_by", "1");
  params.set("include_followed_by", "1");
  params.set("include_want_retweets", "1");
  params.set("include_mute_edge", "1");
  params.set("include_can_dm", "1");
  params.set("include_can_media_tag", "1");
  params.set("include_ext_has_nft_avatar", "1");
  params.set("include_ext_is_blue_verified", "1");
  params.set("include_ext_verified_type", "1");
  params.set("skip_status", "1");
  params.set("cards_platform", "Web-12");
  params.set("include_cards", "1");
  params.set("include_ext_alt_text", "true");
  params.set("include_ext_limited_action_results", "false");
  params.set("include_quote_count", "true");
  params.set("include_reply_count", "1");
  params.set("tweet_mode", "extended");
  params.set("include_ext_collab_control", "true");
  params.set("include_ext_views", "true");
  params.set("include_entities", "true");
  params.set("include_user_entities", "true");
  params.set("include_ext_media_color", "true");
  params.set("include_ext_media_availability", "true");
  params.set("include_ext_sensitive_media_warning", "true");
  params.set("include_ext_trusted_friends_metadata", "true");
  params.set("send_error_codes", "true");
  params.set("simple_quoted_tweet", "true");
  params.set("include_tweet_replies", `${includeTweetReplies}`);
  params.set(
    "ext",
    "mediaStats,highlightedLabel,hasNftAvatar,voiceInfo,birdwatchPivot,enrichments,superFollowMetadata,unmentionInfo,editControl,collab_control,vibe"
  );
  return params;
}

function withTransform(fetchFn, transform) {
  return async (input, init) => {
    const fetchArgs = await transform?.request?.(input, init) ?? [
      input,
      init
    ];
    const res = await fetchFn(...fetchArgs);
    return await transform?.response?.(res) ?? res;
  };
}
class TwitterGuestAuth {
  constructor(bearerToken, options) {
    this.options = options;
    this.fetch = withTransform(options?.fetch ?? fetch, options?.transform);
    this.bearerToken = bearerToken;
    this.jar = new toughCookie.CookieJar();
  }
  cookieJar() {
    return this.jar;
  }
  isLoggedIn() {
    return Promise.resolve(false);
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  login(_username, _password, _email) {
    return this.updateGuestToken();
  }
  logout() {
    this.deleteToken();
    this.jar = new toughCookie.CookieJar();
    return Promise.resolve();
  }
  deleteToken() {
    delete this.guestToken;
    delete this.guestCreatedAt;
  }
  hasToken() {
    return this.guestToken != null;
  }
  authenticatedAt() {
    if (this.guestCreatedAt == null) {
      return null;
    }
    return new Date(this.guestCreatedAt);
  }
  async installTo(headers) {
    if (this.shouldUpdate()) {
      await this.updateGuestToken();
    }
    const token = this.guestToken;
    if (token == null) {
      throw new Error("Authentication token is null or undefined.");
    }
    headers.set("authorization", `Bearer ${this.bearerToken}`);
    headers.set("x-guest-token", token);
    const cookies = await this.getCookies();
    const xCsrfToken = cookies.find((cookie) => cookie.key === "ct0");
    if (xCsrfToken) {
      headers.set("x-csrf-token", xCsrfToken.value);
    }
    headers.set("cookie", await this.getCookieString());
  }
  getCookies() {
    return this.jar.getCookies(this.getCookieJarUrl());
  }
  getCookieString() {
    return this.jar.getCookieString(this.getCookieJarUrl());
  }
  async removeCookie(key) {
    const store = this.jar.store;
    const cookies = await this.jar.getCookies(this.getCookieJarUrl());
    for (const cookie of cookies) {
      if (!cookie.domain || !cookie.path) continue;
      store.removeCookie(cookie.domain, cookie.path, key);
      if (typeof document !== "undefined") {
        document.cookie = `${cookie.key}=; Max-Age=0; path=${cookie.path}; domain=${cookie.domain}`;
      }
    }
  }
  getCookieJarUrl() {
    return typeof document !== "undefined" ? document.location.toString() : "https://twitter.com";
  }
  /**
   * Updates the authentication state with a new guest token from the Twitter API.
   */
  async updateGuestToken() {
    const guestActivateUrl = "https://api.twitter.com/1.1/guest/activate.json";
    const headers = new headersPolyfill.Headers({
      Authorization: `Bearer ${this.bearerToken}`,
      Cookie: await this.getCookieString()
    });
    const res = await this.fetch(guestActivateUrl, {
      method: "POST",
      headers,
      referrerPolicy: "no-referrer"
    });
    await updateCookieJar(this.jar, res.headers);
    if (!res.ok) {
      throw new Error(await res.text());
    }
    const o = await res.json();
    if (o == null || o["guest_token"] == null) {
      throw new Error("guest_token not found.");
    }
    const newGuestToken = o["guest_token"];
    if (typeof newGuestToken !== "string") {
      throw new Error("guest_token was not a string.");
    }
    this.guestToken = newGuestToken;
    this.guestCreatedAt = /* @__PURE__ */ new Date();
  }
  /**
   * Returns if the authentication token needs to be updated or not.
   * @returns `true` if the token needs to be updated; `false` otherwise.
   */
  shouldUpdate() {
    return !this.hasToken() || this.guestCreatedAt != null && this.guestCreatedAt < new Date((/* @__PURE__ */ new Date()).valueOf() - 3 * 60 * 60 * 1e3);
  }
}

const TwitterUserAuthSubtask = typebox.Type.Object({
  subtask_id: typebox.Type.String(),
  enter_text: typebox.Type.Optional(typebox.Type.Object({}))
});
class TwitterUserAuth extends TwitterGuestAuth {
  constructor(bearerToken, options) {
    super(bearerToken, options);
  }
  async isLoggedIn() {
    const res = await requestApi(
      "https://api.twitter.com/1.1/account/verify_credentials.json",
      this
    );
    if (!res.success) {
      return false;
    }
    const { value: verify } = res;
    return verify && !verify.errors?.length;
  }
  async login(username, password, email, twoFactorSecret) {
    await this.updateGuestToken();
    let next = await this.initLogin();
    while ("subtask" in next && next.subtask) {
      if (next.subtask.subtask_id === "LoginJsInstrumentationSubtask") {
        next = await this.handleJsInstrumentationSubtask(next);
      } else if (next.subtask.subtask_id === "LoginEnterUserIdentifierSSO") {
        next = await this.handleEnterUserIdentifierSSO(next, username);
      } else if (next.subtask.subtask_id === "LoginEnterAlternateIdentifierSubtask") {
        next = await this.handleEnterAlternateIdentifierSubtask(
          next,
          email
        );
      } else if (next.subtask.subtask_id === "LoginEnterPassword") {
        next = await this.handleEnterPassword(next, password);
      } else if (next.subtask.subtask_id === "AccountDuplicationCheck") {
        next = await this.handleAccountDuplicationCheck(next);
      } else if (next.subtask.subtask_id === "LoginTwoFactorAuthChallenge") {
        if (twoFactorSecret) {
          next = await this.handleTwoFactorAuthChallenge(next, twoFactorSecret);
        } else {
          throw new Error(
            "Requested two factor authentication code but no secret provided"
          );
        }
      } else if (next.subtask.subtask_id === "LoginAcid") {
        next = await this.handleAcid(next, email);
      } else if (next.subtask.subtask_id === "LoginSuccessSubtask") {
        next = await this.handleSuccessSubtask(next);
      } else {
        throw new Error(`Unknown subtask ${next.subtask.subtask_id}`);
      }
    }
    if ("err" in next) {
      throw next.err;
    }
  }
  async logout() {
    if (!this.isLoggedIn()) {
      return;
    }
    await requestApi(
      "https://api.twitter.com/1.1/account/logout.json",
      this,
      "POST"
    );
    this.deleteToken();
    this.jar = new toughCookie.CookieJar();
  }
  async installCsrfToken(headers) {
    const cookies = await this.getCookies();
    const xCsrfToken = cookies.find((cookie) => cookie.key === "ct0");
    if (xCsrfToken) {
      headers.set("x-csrf-token", xCsrfToken.value);
    }
  }
  async installTo(headers) {
    headers.set("authorization", `Bearer ${this.bearerToken}`);
    headers.set("cookie", await this.getCookieString());
    await this.installCsrfToken(headers);
  }
  async initLogin() {
    this.removeCookie("twitter_ads_id=");
    this.removeCookie("ads_prefs=");
    this.removeCookie("_twitter_sess=");
    this.removeCookie("zipbox_forms_auth_token=");
    this.removeCookie("lang=");
    this.removeCookie("bouncer_reset_cookie=");
    this.removeCookie("twid=");
    this.removeCookie("twitter_ads_idb=");
    this.removeCookie("email_uid=");
    this.removeCookie("external_referer=");
    this.removeCookie("ct0=");
    this.removeCookie("aa_u=");
    return await this.executeFlowTask({
      flow_name: "login",
      input_flow_data: {
        flow_context: {
          debug_overrides: {},
          start_location: {
            location: "splash_screen"
          }
        }
      }
    });
  }
  async handleJsInstrumentationSubtask(prev) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "LoginJsInstrumentationSubtask",
          js_instrumentation: {
            response: "{}",
            link: "next_link"
          }
        }
      ]
    });
  }
  async handleEnterAlternateIdentifierSubtask(prev, email) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "LoginEnterAlternateIdentifierSubtask",
          enter_text: {
            text: email,
            link: "next_link"
          }
        }
      ]
    });
  }
  async handleEnterUserIdentifierSSO(prev, username) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "LoginEnterUserIdentifierSSO",
          settings_list: {
            setting_responses: [
              {
                key: "user_identifier",
                response_data: {
                  text_data: { result: username }
                }
              }
            ],
            link: "next_link"
          }
        }
      ]
    });
  }
  async handleEnterPassword(prev, password) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "LoginEnterPassword",
          enter_password: {
            password,
            link: "next_link"
          }
        }
      ]
    });
  }
  async handleAccountDuplicationCheck(prev) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "AccountDuplicationCheck",
          check_logged_in_account: {
            link: "AccountDuplicationCheck_false"
          }
        }
      ]
    });
  }
  async handleTwoFactorAuthChallenge(prev, secret) {
    const totp = new OTPAuth__namespace.TOTP({ secret });
    let error;
    for (let attempts = 1; attempts < 4; attempts += 1) {
      try {
        return await this.executeFlowTask({
          flow_token: prev.flowToken,
          subtask_inputs: [
            {
              subtask_id: "LoginTwoFactorAuthChallenge",
              enter_text: {
                link: "next_link",
                text: totp.generate()
              }
            }
          ]
        });
      } catch (err) {
        error = err;
        await new Promise((resolve) => setTimeout(resolve, 2e3 * attempts));
      }
    }
    throw error;
  }
  async handleAcid(prev, email) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: [
        {
          subtask_id: "LoginAcid",
          enter_text: {
            text: email,
            link: "next_link"
          }
        }
      ]
    });
  }
  async handleSuccessSubtask(prev) {
    return await this.executeFlowTask({
      flow_token: prev.flowToken,
      subtask_inputs: []
    });
  }
  async executeFlowTask(data) {
    const onboardingTaskUrl = "https://api.twitter.com/1.1/onboarding/task.json";
    const token = this.guestToken;
    if (token == null) {
      throw new Error("Authentication token is null or undefined.");
    }
    const headers = new headersPolyfill.Headers({
      authorization: `Bearer ${this.bearerToken}`,
      cookie: await this.getCookieString(),
      "content-type": "application/json",
      "User-Agent": "Mozilla/5.0 (Linux; Android 11; Nokia G20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.88 Mobile Safari/537.36",
      "x-guest-token": token,
      "x-twitter-auth-type": "OAuth2Client",
      "x-twitter-active-user": "yes",
      "x-twitter-client-language": "en"
    });
    await this.installCsrfToken(headers);
    const res = await this.fetch(onboardingTaskUrl, {
      credentials: "include",
      method: "POST",
      headers,
      body: JSON.stringify(data)
    });
    await updateCookieJar(this.jar, res.headers);
    if (!res.ok) {
      return { status: "error", err: new Error(await res.text()) };
    }
    const flow = await res.json();
    if (flow?.flow_token == null) {
      return { status: "error", err: new Error("flow_token not found.") };
    }
    if (flow.errors?.length) {
      return {
        status: "error",
        err: new Error(
          `Authentication error (${flow.errors[0].code}): ${flow.errors[0].message}`
        )
      };
    }
    if (typeof flow.flow_token !== "string") {
      return {
        status: "error",
        err: new Error("flow_token was not a string.")
      };
    }
    const subtask = flow.subtasks?.length ? flow.subtasks[0] : void 0;
    value.Check(TwitterUserAuthSubtask, subtask);
    if (subtask && subtask.subtask_id === "DenyLoginSubtask") {
      return {
        status: "error",
        err: new Error("Authentication error: DenyLoginSubtask")
      };
    }
    return {
      status: "success",
      subtask,
      flowToken: flow.flow_token
    };
  }
}

function getAvatarOriginalSizeUrl(avatarUrl) {
  return avatarUrl ? avatarUrl.replace("_normal", "") : void 0;
}
function parseProfile(user, isBlueVerified) {
  const profile = {
    avatar: getAvatarOriginalSizeUrl(user.profile_image_url_https),
    banner: user.profile_banner_url,
    biography: user.description,
    followersCount: user.followers_count,
    followingCount: user.friends_count,
    friendsCount: user.friends_count,
    mediaCount: user.media_count,
    isPrivate: user.protected ?? false,
    isVerified: user.verified,
    likesCount: user.favourites_count,
    listedCount: user.listed_count,
    location: user.location,
    name: user.name,
    pinnedTweetIds: user.pinned_tweet_ids_str,
    tweetsCount: user.statuses_count,
    url: `https://twitter.com/${user.screen_name}`,
    userId: user.id_str,
    username: user.screen_name,
    isBlueVerified: isBlueVerified ?? false,
    canDm: user.can_dm
  };
  if (user.created_at != null) {
    profile.joined = new Date(Date.parse(user.created_at));
  }
  const urls = user.entities?.url?.urls;
  if (urls?.length != null && urls?.length > 0) {
    profile.website = urls[0].expanded_url;
  }
  return profile;
}
async function getProfile(username, auth) {
  const params = new URLSearchParams();
  params.set(
    "variables",
    stringify({
      screen_name: username,
      withSafetyModeUserFields: true
    })
  );
  params.set(
    "features",
    stringify({
      hidden_profile_likes_enabled: false,
      hidden_profile_subscriptions_enabled: false,
      // Auth-restricted
      responsive_web_graphql_exclude_directive_enabled: true,
      verified_phone_label_enabled: false,
      subscriptions_verification_info_is_identity_verified_enabled: false,
      subscriptions_verification_info_verified_since_enabled: true,
      highlights_tweets_tab_ui_enabled: true,
      creator_subscriptions_tweet_preview_api_enabled: true,
      responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
      responsive_web_graphql_timeline_navigation_enabled: true
    })
  );
  params.set("fieldToggles", stringify({ withAuxiliaryUserLabels: false }));
  const res = await requestApi(
    `https://twitter.com/i/api/graphql/G3KGOASz96M-Qu0nwmGXNg/UserByScreenName?${params.toString()}`,
    auth
  );
  if (!res.success) {
    return res;
  }
  const { value } = res;
  const { errors } = value;
  if (errors != null && errors.length > 0) {
    return {
      success: false,
      err: new Error(errors[0].message)
    };
  }
  if (!value.data || !value.data.user || !value.data.user.result) {
    return {
      success: false,
      err: new Error("User not found.")
    };
  }
  const { result: user } = value.data.user;
  const { legacy } = user;
  if (user.rest_id == null || user.rest_id.length === 0) {
    return {
      success: false,
      err: new Error("rest_id not found.")
    };
  }
  legacy.id_str = user.rest_id;
  if (legacy.screen_name == null || legacy.screen_name.length === 0) {
    return {
      success: false,
      err: new Error(`Either ${username} does not exist or is private.`)
    };
  }
  return {
    success: true,
    value: parseProfile(user.legacy, user.is_blue_verified)
  };
}
const idCache = /* @__PURE__ */ new Map();
async function getUserIdByScreenName(screenName, auth) {
  const cached = idCache.get(screenName);
  if (cached != null) {
    return { success: true, value: cached };
  }
  const profileRes = await getProfile(screenName, auth);
  if (!profileRes.success) {
    return profileRes;
  }
  const profile = profileRes.value;
  if (profile.userId != null) {
    idCache.set(screenName, profile.userId);
    return {
      success: true,
      value: profile.userId
    };
  }
  return {
    success: false,
    err: new Error("User ID is undefined.")
  };
}

async function* getUserTimeline(query, maxProfiles, fetchFunc) {
  let nProfiles = 0;
  let cursor = void 0;
  let consecutiveEmptyBatches = 0;
  while (nProfiles < maxProfiles) {
    const batch = await fetchFunc(
      query,
      maxProfiles,
      cursor
    );
    const { profiles, next } = batch;
    cursor = next;
    if (profiles.length === 0) {
      consecutiveEmptyBatches++;
      if (consecutiveEmptyBatches > 5) break;
    } else consecutiveEmptyBatches = 0;
    for (const profile of profiles) {
      if (nProfiles < maxProfiles) yield profile;
      else break;
      nProfiles++;
    }
    if (!next) break;
  }
}
async function* getTweetTimeline(query, maxTweets, fetchFunc) {
  let nTweets = 0;
  let cursor = void 0;
  while (nTweets < maxTweets) {
    const batch = await fetchFunc(
      query,
      maxTweets,
      cursor
    );
    const { tweets, next } = batch;
    if (tweets.length === 0) {
      break;
    }
    for (const tweet of tweets) {
      if (nTweets < maxTweets) {
        cursor = next;
        yield tweet;
      } else {
        break;
      }
      nTweets++;
    }
  }
  return cursor;
}

function isFieldDefined(key) {
  return function(value) {
    return isDefined(value[key]);
  };
}
function isDefined(value) {
  return value != null;
}

const reHashtag = /\B(\#\S+\b)/g;
const reCashtag = /\B(\$\S+\b)/g;
const reTwitterUrl = /https:(\/\/t\.co\/([A-Za-z0-9]|[A-Za-z]){10})/g;
const reUsername = /\B(\@\S{1,15}\b)/g;
function parseMediaGroups(media) {
  const photos = [];
  const videos = [];
  let sensitiveContent = void 0;
  for (const m of media.filter(isFieldDefined("id_str")).filter(isFieldDefined("media_url_https"))) {
    if (m.type === "photo") {
      photos.push({
        id: m.id_str,
        url: m.media_url_https,
        alt_text: m.ext_alt_text
      });
    } else if (m.type === "video") {
      videos.push(parseVideo(m));
    }
    const sensitive = m.ext_sensitive_media_warning;
    if (sensitive != null) {
      sensitiveContent = sensitive.adult_content || sensitive.graphic_violence || sensitive.other;
    }
  }
  return { sensitiveContent, photos, videos };
}
function parseVideo(m) {
  const video = {
    id: m.id_str,
    preview: m.media_url_https
  };
  let maxBitrate = 0;
  const variants = m.video_info?.variants ?? [];
  for (const variant of variants) {
    const bitrate = variant.bitrate;
    if (bitrate != null && bitrate > maxBitrate && variant.url != null) {
      let variantUrl = variant.url;
      const stringStart = 0;
      const tagSuffixIdx = variantUrl.indexOf("?tag=10");
      if (tagSuffixIdx !== -1) {
        variantUrl = variantUrl.substring(stringStart, tagSuffixIdx + 1);
      }
      video.url = variantUrl;
      maxBitrate = bitrate;
    }
  }
  return video;
}
function reconstructTweetHtml(tweet, photos, videos) {
  const media = [];
  let html = tweet.full_text ?? "";
  html = html.replace(reHashtag, linkHashtagHtml);
  html = html.replace(reCashtag, linkCashtagHtml);
  html = html.replace(reUsername, linkUsernameHtml);
  html = html.replace(reTwitterUrl, unwrapTcoUrlHtml(tweet, media));
  for (const { url } of photos) {
    if (media.indexOf(url) !== -1) {
      continue;
    }
    html += `<br><img src="${url}"/>`;
  }
  for (const { preview: url } of videos) {
    if (media.indexOf(url) !== -1) {
      continue;
    }
    html += `<br><img src="${url}"/>`;
  }
  html = html.replace(/\n/g, "<br>");
  return html;
}
function linkHashtagHtml(hashtag) {
  return `<a href="https://twitter.com/hashtag/${hashtag.replace(
    "#",
    ""
  )}">${hashtag}</a>`;
}
function linkCashtagHtml(cashtag) {
  return `<a href="https://twitter.com/search?q=%24${cashtag.replace(
    "$",
    ""
  )}">${cashtag}</a>`;
}
function linkUsernameHtml(username) {
  return `<a href="https://twitter.com/${username.replace(
    "@",
    ""
  )}">${username}</a>`;
}
function unwrapTcoUrlHtml(tweet, foundedMedia) {
  return function(tco) {
    for (const entity of tweet.entities?.urls ?? []) {
      if (tco === entity.url && entity.expanded_url != null) {
        return `<a href="${entity.expanded_url}">${tco}</a>`;
      }
    }
    for (const entity of tweet.extended_entities?.media ?? []) {
      if (tco === entity.url && entity.media_url_https != null) {
        foundedMedia.push(entity.media_url_https);
        return `<br><a href="${tco}"><img src="${entity.media_url_https}"/></a>`;
      }
    }
    return tco;
  };
}

function getLegacyTweetId(tweet) {
  if (tweet.id_str) {
    return tweet.id_str;
  }
  return tweet.conversation_id_str;
}
function parseLegacyTweet(user, tweet, editControl) {
  if (tweet == null) {
    return {
      success: false,
      err: new Error("Tweet was not found in the timeline object.")
    };
  }
  if (user == null) {
    return {
      success: false,
      err: new Error("User was not found in the timeline object.")
    };
  }
  const tweetId = getLegacyTweetId(tweet);
  if (!tweetId) {
    return {
      success: false,
      err: new Error("Tweet ID was not found in object.")
    };
  }
  const hashtags = tweet.entities?.hashtags ?? [];
  const mentions = tweet.entities?.user_mentions ?? [];
  const media = tweet.extended_entities?.media ?? [];
  const pinnedTweets = new Set(
    user.pinned_tweet_ids_str ?? []
  );
  const urls = tweet.entities?.urls ?? [];
  const { photos, videos, sensitiveContent } = parseMediaGroups(media);
  const tweetVersions = editControl?.edit_tweet_ids ?? [tweetId];
  const editIds = tweetVersions.filter((id) => id !== tweetId);
  const tw = {
    __raw_UNSTABLE: tweet,
    bookmarkCount: tweet.bookmark_count,
    conversationId: tweet.conversation_id_str,
    id: tweetId,
    hashtags: hashtags.filter(isFieldDefined("text")).map((hashtag) => hashtag.text),
    likes: tweet.favorite_count,
    mentions: mentions.filter(isFieldDefined("id_str")).map((mention) => ({
      id: mention.id_str,
      username: mention.screen_name,
      name: mention.name
    })),
    name: user.name,
    permanentUrl: `https://twitter.com/${user.screen_name}/status/${tweetId}`,
    photos,
    replies: tweet.reply_count,
    retweets: tweet.retweet_count,
    text: tweet.full_text,
    thread: [],
    urls: urls.filter(isFieldDefined("expanded_url")).map((url) => url.expanded_url),
    userId: tweet.user_id_str,
    username: user.screen_name,
    videos,
    isQuoted: false,
    isReply: false,
    isEdited: editIds.length > 1,
    versions: tweetVersions,
    isRetweet: false,
    isPin: false,
    sensitiveContent: false
  };
  if (tweet.created_at) {
    tw.timeParsed = new Date(Date.parse(tweet.created_at));
    tw.timestamp = Math.floor(tw.timeParsed.valueOf() / 1e3);
  }
  if (tweet.place?.id) {
    tw.place = tweet.place;
  }
  const quotedStatusIdStr = tweet.quoted_status_id_str;
  const inReplyToStatusIdStr = tweet.in_reply_to_status_id_str;
  const retweetedStatusIdStr = tweet.retweeted_status_id_str;
  const retweetedStatusResult = tweet.retweeted_status_result?.result;
  if (quotedStatusIdStr) {
    tw.isQuoted = true;
    tw.quotedStatusId = quotedStatusIdStr;
  }
  if (inReplyToStatusIdStr) {
    tw.isReply = true;
    tw.inReplyToStatusId = inReplyToStatusIdStr;
  }
  if (retweetedStatusIdStr || retweetedStatusResult) {
    tw.isRetweet = true;
    tw.retweetedStatusId = retweetedStatusIdStr;
    if (retweetedStatusResult) {
      const parsedResult = parseLegacyTweet(
        retweetedStatusResult?.core?.user_results?.result?.legacy,
        retweetedStatusResult?.legacy
      );
      if (parsedResult.success) {
        tw.retweetedStatus = parsedResult.tweet;
      }
    }
  }
  const views = parseInt(tweet.ext_views?.count ?? "");
  if (!isNaN(views)) {
    tw.views = views;
  }
  if (pinnedTweets.has(tweetId)) {
    tw.isPin = true;
  }
  if (sensitiveContent) {
    tw.sensitiveContent = true;
  }
  tw.html = reconstructTweetHtml(tweet, tw.photos, tw.videos);
  return { success: true, tweet: tw };
}
function parseResult(result) {
  const noteTweetResultText = result?.note_tweet?.note_tweet_results?.result?.text;
  if (result?.legacy && noteTweetResultText) {
    result.legacy.full_text = noteTweetResultText;
  }
  const tweetResult = parseLegacyTweet(
    result?.core?.user_results?.result?.legacy,
    result?.legacy
  );
  if (!tweetResult.success) {
    return tweetResult;
  }
  if (!tweetResult.tweet.views && result?.views?.count) {
    const views = parseInt(result.views.count);
    if (!isNaN(views)) {
      tweetResult.tweet.views = views;
    }
  }
  const quotedResult = result?.quoted_status_result?.result;
  if (quotedResult) {
    if (quotedResult.legacy && quotedResult.rest_id) {
      quotedResult.legacy.id_str = quotedResult.rest_id;
    }
    const quotedTweetResult = parseResult(quotedResult);
    if (quotedTweetResult.success) {
      tweetResult.tweet.quotedStatus = quotedTweetResult.tweet;
    }
  }
  return tweetResult;
}
const expectedEntryTypes = ["tweet", "profile-conversation"];
function parseTimelineTweetsV2(timeline) {
  let bottomCursor;
  let topCursor;
  const tweets = [];
  const instructions = timeline.data?.user?.result?.timeline_v2?.timeline?.instructions ?? [];
  for (const instruction of instructions) {
    const entries = instruction.entries ?? [];
    for (const entry of entries) {
      const entryContent = entry.content;
      if (!entryContent) continue;
      if (entryContent.cursorType === "Bottom") {
        bottomCursor = entryContent.value;
        continue;
      } else if (entryContent.cursorType === "Top") {
        topCursor = entryContent.value;
        continue;
      }
      const idStr = entry.entryId;
      if (!expectedEntryTypes.some((entryType) => idStr.startsWith(entryType))) {
        continue;
      }
      if (entryContent.itemContent) {
        parseAndPush(tweets, entryContent.itemContent, idStr);
      } else if (entryContent.items) {
        for (const item of entryContent.items) {
          if (item.item?.itemContent) {
            parseAndPush(tweets, item.item.itemContent, idStr);
          }
        }
      }
    }
  }
  return { tweets, next: bottomCursor, previous: topCursor };
}
function parseTimelineEntryItemContentRaw(content, entryId, isConversation = false) {
  let result = content.tweet_results?.result ?? content.tweetResult?.result;
  if (result?.__typename === "Tweet" || result?.__typename === "TweetWithVisibilityResults" && result?.tweet) {
    if (result?.__typename === "TweetWithVisibilityResults")
      result = result.tweet;
    if (result?.legacy) {
      result.legacy.id_str = result.rest_id ?? entryId.replace("conversation-", "").replace("tweet-", "");
    }
    const tweetResult = parseResult(result);
    if (tweetResult.success) {
      if (isConversation) {
        if (content?.tweetDisplayType === "SelfThread") {
          tweetResult.tweet.isSelfThread = true;
        }
      }
      return tweetResult.tweet;
    }
  }
  return null;
}
function parseAndPush(tweets, content, entryId, isConversation = false) {
  const tweet = parseTimelineEntryItemContentRaw(
    content,
    entryId,
    isConversation
  );
  if (tweet) {
    tweets.push(tweet);
  }
}
function parseThreadedConversation(conversation) {
  const tweets = [];
  const instructions = conversation.data?.threaded_conversation_with_injections_v2?.instructions ?? [];
  for (const instruction of instructions) {
    const entries = instruction.entries ?? [];
    for (const entry of entries) {
      const entryContent = entry.content?.itemContent;
      if (entryContent) {
        parseAndPush(tweets, entryContent, entry.entryId, true);
      }
      for (const item of entry.content?.items ?? []) {
        const itemContent = item.item?.itemContent;
        if (itemContent) {
          parseAndPush(tweets, itemContent, entry.entryId, true);
        }
      }
    }
  }
  for (const tweet of tweets) {
    if (tweet.inReplyToStatusId) {
      for (const parentTweet of tweets) {
        if (parentTweet.id === tweet.inReplyToStatusId) {
          tweet.inReplyToStatus = parentTweet;
          break;
        }
      }
    }
    if (tweet.isSelfThread && tweet.conversationId === tweet.id) {
      for (const childTweet of tweets) {
        if (childTweet.isSelfThread && childTweet.id !== tweet.id) {
          tweet.thread.push(childTweet);
        }
      }
      if (tweet.thread.length === 0) {
        tweet.isSelfThread = false;
      }
    }
  }
  return tweets;
}

function parseSearchTimelineTweets(timeline) {
  let bottomCursor;
  let topCursor;
  const tweets = [];
  const instructions = timeline.data?.search_by_raw_query?.search_timeline?.timeline?.instructions ?? [];
  for (const instruction of instructions) {
    if (instruction.type === "TimelineAddEntries" || instruction.type === "TimelineReplaceEntry") {
      if (instruction.entry?.content?.cursorType === "Bottom") {
        bottomCursor = instruction.entry.content.value;
        continue;
      } else if (instruction.entry?.content?.cursorType === "Top") {
        topCursor = instruction.entry.content.value;
        continue;
      }
      const entries = instruction.entries ?? [];
      for (const entry of entries) {
        const itemContent = entry.content?.itemContent;
        if (itemContent?.tweetDisplayType === "Tweet") {
          const tweetResultRaw = itemContent.tweet_results?.result;
          const tweetResult = parseLegacyTweet(
            tweetResultRaw?.core?.user_results?.result?.legacy,
            tweetResultRaw?.legacy,
            tweetResultRaw?.edit_control?.edit_control_initial
          );
          if (tweetResult.success) {
            if (!tweetResult.tweet.views && tweetResultRaw?.views?.count) {
              const views = parseInt(tweetResultRaw.views.count);
              if (!isNaN(views)) {
                tweetResult.tweet.views = views;
              }
            }
            tweets.push(tweetResult.tweet);
          }
        } else if (entry.content?.cursorType === "Bottom") {
          bottomCursor = entry.content.value;
        } else if (entry.content?.cursorType === "Top") {
          topCursor = entry.content.value;
        }
      }
    }
  }
  return { tweets, next: bottomCursor, previous: topCursor };
}
function parseSearchTimelineUsers(timeline) {
  let bottomCursor;
  let topCursor;
  const profiles = [];
  const instructions = timeline.data?.search_by_raw_query?.search_timeline?.timeline?.instructions ?? [];
  for (const instruction of instructions) {
    if (instruction.type === "TimelineAddEntries" || instruction.type === "TimelineReplaceEntry") {
      if (instruction.entry?.content?.cursorType === "Bottom") {
        bottomCursor = instruction.entry.content.value;
        continue;
      } else if (instruction.entry?.content?.cursorType === "Top") {
        topCursor = instruction.entry.content.value;
        continue;
      }
      const entries = instruction.entries ?? [];
      for (const entry of entries) {
        const itemContent = entry.content?.itemContent;
        if (itemContent?.userDisplayType === "User") {
          const userResultRaw = itemContent.user_results?.result;
          if (userResultRaw?.legacy) {
            const profile = parseProfile(
              userResultRaw.legacy,
              userResultRaw.is_blue_verified
            );
            if (!profile.userId) {
              profile.userId = userResultRaw.rest_id;
            }
            profiles.push(profile);
          }
        } else if (entry.content?.cursorType === "Bottom") {
          bottomCursor = entry.content.value;
        } else if (entry.content?.cursorType === "Top") {
          topCursor = entry.content.value;
        }
      }
    }
  }
  return { profiles, next: bottomCursor, previous: topCursor };
}

var SearchMode = /* @__PURE__ */ ((SearchMode2) => {
  SearchMode2[SearchMode2["Top"] = 0] = "Top";
  SearchMode2[SearchMode2["Latest"] = 1] = "Latest";
  SearchMode2[SearchMode2["Photos"] = 2] = "Photos";
  SearchMode2[SearchMode2["Videos"] = 3] = "Videos";
  SearchMode2[SearchMode2["Users"] = 4] = "Users";
  return SearchMode2;
})(SearchMode || {});
function searchTweets(query, maxTweets, searchMode, auth) {
  return getTweetTimeline(query, maxTweets, (q, mt, c) => {
    return fetchSearchTweets(q, mt, searchMode, auth, c);
  });
}
function searchProfiles(query, maxProfiles, auth) {
  return getUserTimeline(query, maxProfiles, (q, mt, c) => {
    return fetchSearchProfiles(q, mt, auth, c);
  });
}
async function fetchSearchTweets(query, maxTweets, searchMode, auth, cursor) {
  const timeline = await getSearchTimeline(
    query,
    maxTweets,
    searchMode,
    auth,
    cursor
  );
  return parseSearchTimelineTweets(timeline);
}
async function fetchSearchProfiles(query, maxProfiles, auth, cursor) {
  const timeline = await getSearchTimeline(
    query,
    maxProfiles,
    4 /* Users */,
    auth,
    cursor
  );
  return parseSearchTimelineUsers(timeline);
}
async function getSearchTimeline(query, maxItems, searchMode, auth, cursor) {
  if (!auth.isLoggedIn()) {
    throw new Error("Scraper is not logged-in for search.");
  }
  if (maxItems > 50) {
    maxItems = 50;
  }
  const variables = {
    rawQuery: query,
    count: maxItems,
    querySource: "typed_query",
    product: "Top"
  };
  const features = addApiFeatures({
    longform_notetweets_inline_media_enabled: true,
    responsive_web_enhance_cards_enabled: false,
    responsive_web_media_download_video_enabled: false,
    responsive_web_twitter_article_tweet_consumption_enabled: false,
    tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
    interactive_text_enabled: false,
    responsive_web_text_conversations_enabled: false,
    vibe_api_enabled: false
  });
  const fieldToggles = {
    withArticleRichContentState: false
  };
  if (cursor != null && cursor != "") {
    variables["cursor"] = cursor;
  }
  switch (searchMode) {
    case 1 /* Latest */:
      variables.product = "Latest";
      break;
    case 2 /* Photos */:
      variables.product = "Photos";
      break;
    case 3 /* Videos */:
      variables.product = "Videos";
      break;
    case 4 /* Users */:
      variables.product = "People";
      break;
  }
  const params = new URLSearchParams();
  params.set("features", stringify(features));
  params.set("fieldToggles", stringify(fieldToggles));
  params.set("variables", stringify(variables));
  const res = await requestApi(
    `https://api.twitter.com/graphql/gkjsKepM6gl_HmFWoWKfgg/SearchTimeline?${params.toString()}`,
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return res.value;
}

function parseRelationshipTimeline(timeline) {
  let bottomCursor;
  let topCursor;
  const profiles = [];
  const instructions = timeline.data?.user?.result?.timeline?.timeline?.instructions ?? [];
  for (const instruction of instructions) {
    if (instruction.type === "TimelineAddEntries" || instruction.type === "TimelineReplaceEntry") {
      if (instruction.entry?.content?.cursorType === "Bottom") {
        bottomCursor = instruction.entry.content.value;
        continue;
      }
      if (instruction.entry?.content?.cursorType === "Top") {
        topCursor = instruction.entry.content.value;
        continue;
      }
      const entries = instruction.entries ?? [];
      for (const entry of entries) {
        const itemContent = entry.content?.itemContent;
        if (itemContent?.userDisplayType === "User") {
          const userResultRaw = itemContent.user_results?.result;
          if (userResultRaw?.legacy) {
            const profile = parseProfile(
              userResultRaw.legacy,
              userResultRaw.is_blue_verified
            );
            if (!profile.userId) {
              profile.userId = userResultRaw.rest_id;
            }
            profiles.push(profile);
          }
        } else if (entry.content?.cursorType === "Bottom") {
          bottomCursor = entry.content.value;
        } else if (entry.content?.cursorType === "Top") {
          topCursor = entry.content.value;
        }
      }
    }
  }
  return { profiles, next: bottomCursor, previous: topCursor };
}

function getFollowing(userId, maxProfiles, auth) {
  return getUserTimeline(userId, maxProfiles, (q, mt, c) => {
    return fetchProfileFollowing(q, mt, auth, c);
  });
}
function getFollowers(userId, maxProfiles, auth) {
  return getUserTimeline(userId, maxProfiles, (q, mt, c) => {
    return fetchProfileFollowers(q, mt, auth, c);
  });
}
async function fetchProfileFollowing(userId, maxProfiles, auth, cursor) {
  const timeline = await getFollowingTimeline(
    userId,
    maxProfiles,
    auth,
    cursor
  );
  return parseRelationshipTimeline(timeline);
}
async function fetchProfileFollowers(userId, maxProfiles, auth, cursor) {
  const timeline = await getFollowersTimeline(
    userId,
    maxProfiles,
    auth,
    cursor
  );
  return parseRelationshipTimeline(timeline);
}
async function getFollowingTimeline(userId, maxItems, auth, cursor) {
  if (!auth.isLoggedIn()) {
    throw new Error("Scraper is not logged-in for profile following.");
  }
  if (maxItems > 50) {
    maxItems = 50;
  }
  const variables = {
    userId,
    count: maxItems,
    includePromotedContent: false
  };
  const features = addApiFeatures({
    responsive_web_twitter_article_tweet_consumption_enabled: false,
    tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
    longform_notetweets_inline_media_enabled: true,
    responsive_web_media_download_video_enabled: false
  });
  if (cursor != null && cursor != "") {
    variables["cursor"] = cursor;
  }
  const params = new URLSearchParams();
  params.set("features", stringify(features));
  params.set("variables", stringify(variables));
  const res = await requestApi(
    `https://twitter.com/i/api/graphql/iSicc7LrzWGBgDPL0tM_TQ/Following?${params.toString()}`,
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return res.value;
}
async function getFollowersTimeline(userId, maxItems, auth, cursor) {
  if (!auth.isLoggedIn()) {
    throw new Error("Scraper is not logged-in for profile followers.");
  }
  if (maxItems > 50) {
    maxItems = 50;
  }
  const variables = {
    userId,
    count: maxItems,
    includePromotedContent: false
  };
  const features = addApiFeatures({
    responsive_web_twitter_article_tweet_consumption_enabled: false,
    tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
    longform_notetweets_inline_media_enabled: true,
    responsive_web_media_download_video_enabled: false
  });
  if (cursor != null && cursor != "") {
    variables["cursor"] = cursor;
  }
  const params = new URLSearchParams();
  params.set("features", stringify(features));
  params.set("variables", stringify(variables));
  const res = await requestApi(
    `https://twitter.com/i/api/graphql/rRXFSG5vR6drKr5M37YOTw/Followers?${params.toString()}`,
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return res.value;
}

async function getTrends(auth) {
  const params = new URLSearchParams();
  addApiParams(params, false);
  params.set("count", "20");
  params.set("candidate_source", "trends");
  params.set("include_page_configuration", "false");
  params.set("entity_tokens", "false");
  const res = await requestApi(
    `https://api.twitter.com/2/guide.json?${params.toString()}`,
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  const instructions = res.value.timeline?.instructions ?? [];
  if (instructions.length < 2) {
    throw new Error("No trend entries found.");
  }
  const entries = instructions[1].addEntries?.entries ?? [];
  if (entries.length < 2) {
    throw new Error("No trend entries found.");
  }
  const items = entries[1].content?.timelineModule?.items ?? [];
  const trends = [];
  for (const item of items) {
    const trend = item.item?.clientEventInfo?.details?.guideDetails?.transparentGuideDetails?.trendMetadata?.trendName;
    if (trend != null) {
      trends.push(trend);
    }
  }
  return trends;
}

const endpoints = {
  // TODO: Migrate other endpoint URLs here
  UserTweets: "https://twitter.com/i/api/graphql/V7H0Ap3_Hh2FyS75OCDO3Q/UserTweets?variables=%7B%22userId%22%3A%224020276615%22%2C%22count%22%3A20%2C%22includePromotedContent%22%3Atrue%2C%22withQuickPromoteEligibilityTweetFields%22%3Atrue%2C%22withVoice%22%3Atrue%2C%22withV2Timeline%22%3Atrue%7D&features=%7B%22rweb_tipjar_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22communities_web_enable_tweet_community_results_fetch%22%3Atrue%2C%22c9s_tweet_anatomy_moderator_badge_enabled%22%3Atrue%2C%22articles_preview_enabled%22%3Atrue%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Atrue%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22creator_subscriptions_quote_tweet_preview_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22rweb_video_timestamps_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D&fieldToggles=%7B%22withArticlePlainText%22%3Afalse%7D",
  UserTweetsAndReplies: "https://twitter.com/i/api/graphql/E4wA5vo2sjVyvpliUffSCw/UserTweetsAndReplies?variables=%7B%22userId%22%3A%224020276615%22%2C%22count%22%3A40%2C%22cursor%22%3A%22DAABCgABGPWl-F-ATiIKAAIY9YfiF1rRAggAAwAAAAEAAA%22%2C%22includePromotedContent%22%3Atrue%2C%22withCommunity%22%3Atrue%2C%22withVoice%22%3Atrue%2C%22withV2Timeline%22%3Atrue%7D&features=%7B%22rweb_tipjar_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22communities_web_enable_tweet_community_results_fetch%22%3Atrue%2C%22c9s_tweet_anatomy_moderator_badge_enabled%22%3Atrue%2C%22articles_preview_enabled%22%3Atrue%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Atrue%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22creator_subscriptions_quote_tweet_preview_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22rweb_video_timestamps_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D&fieldToggles=%7B%22withArticlePlainText%22%3Afalse%7D",
  UserLikedTweets: "https://twitter.com/i/api/graphql/eSSNbhECHHWWALkkQq-YTA/Likes?variables=%7B%22userId%22%3A%222244196397%22%2C%22count%22%3A20%2C%22includePromotedContent%22%3Afalse%2C%22withClientEventToken%22%3Afalse%2C%22withBirdwatchNotes%22%3Afalse%2C%22withVoice%22%3Atrue%2C%22withV2Timeline%22%3Atrue%7D&features=%7B%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22c9s_tweet_anatomy_moderator_badge_enabled%22%3Atrue%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Atrue%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22rweb_video_timestamps_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D",
  TweetDetail: "https://twitter.com/i/api/graphql/xOhkmRac04YFZmOzU9PJHg/TweetDetail?variables=%7B%22focalTweetId%22%3A%221237110546383724547%22%2C%22with_rux_injections%22%3Afalse%2C%22includePromotedContent%22%3Atrue%2C%22withCommunity%22%3Atrue%2C%22withQuickPromoteEligibilityTweetFields%22%3Atrue%2C%22withBirdwatchNotes%22%3Atrue%2C%22withVoice%22%3Atrue%2C%22withV2Timeline%22%3Atrue%7D&features=%7B%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Afalse%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_media_download_video_enabled%22%3Afalse%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D&fieldToggles=%7B%22withArticleRichContentState%22%3Afalse%7D",
  TweetResultByRestId: "https://twitter.com/i/api/graphql/DJS3BdhUhcaEpZ7B7irJDg/TweetResultByRestId?variables=%7B%22tweetId%22%3A%221237110546383724547%22%2C%22withCommunity%22%3Afalse%2C%22includePromotedContent%22%3Afalse%2C%22withVoice%22%3Afalse%7D&features=%7B%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Afalse%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22responsive_web_media_download_video_enabled%22%3Afalse%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D",
  ListTweets: "https://twitter.com/i/api/graphql/whF0_KH1fCkdLLoyNPMoEw/ListLatestTweetsTimeline?variables=%7B%22listId%22%3A%221736495155002106192%22%2C%22count%22%3A20%7D&features=%7B%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22c9s_tweet_anatomy_moderator_badge_enabled%22%3Atrue%2C%22tweetypie_unmention_optimization_enabled%22%3Atrue%2C%22responsive_web_edit_tweet_api_enabled%22%3Atrue%2C%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3Atrue%2C%22view_counts_everywhere_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_twitter_article_tweet_consumption_enabled%22%3Afalse%2C%22tweet_awards_web_tipping_enabled%22%3Afalse%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%2C%22standardized_nudges_misinfo%22%3Atrue%2C%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3Atrue%2C%22rweb_video_timestamps_enabled%22%3Atrue%2C%22longform_notetweets_rich_text_read_enabled%22%3Atrue%2C%22longform_notetweets_inline_media_enabled%22%3Atrue%2C%22responsive_web_media_download_video_enabled%22%3Afalse%2C%22responsive_web_enhance_cards_enabled%22%3Afalse%7D"
};
class ApiRequest {
  constructor(info) {
    this.url = info.url;
    this.variables = info.variables;
    this.features = info.features;
    this.fieldToggles = info.fieldToggles;
  }
  toRequestUrl() {
    const params = new URLSearchParams();
    if (this.variables) {
      params.set("variables", stringify(this.variables));
    }
    if (this.features) {
      params.set("features", stringify(this.features));
    }
    if (this.fieldToggles) {
      params.set("fieldToggles", stringify(this.fieldToggles));
    }
    return `${this.url}?${params.toString()}`;
  }
}
function parseEndpointExample(example) {
  const { protocol, host, pathname, searchParams: query } = new URL(example);
  const base = `${protocol}//${host}${pathname}`;
  const variables = query.get("variables");
  const features = query.get("features");
  const fieldToggles = query.get("fieldToggles");
  return new ApiRequest({
    url: base,
    variables: variables ? JSON.parse(variables) : void 0,
    features: features ? JSON.parse(features) : void 0,
    fieldToggles: fieldToggles ? JSON.parse(fieldToggles) : void 0
  });
}
function createApiRequestFactory(endpoints2) {
  return Object.entries(endpoints2).map(([endpointName, endpointExample]) => {
    return {
      [`create${endpointName}Request`]: () => {
        return parseEndpointExample(endpointExample);
      }
    };
  }).reduce((agg, next) => {
    return Object.assign(agg, next);
  });
}
const apiRequestFactory = createApiRequestFactory(endpoints);

function parseListTimelineTweets(timeline) {
  let bottomCursor;
  let topCursor;
  const tweets = [];
  const instructions = timeline.data?.list?.tweets_timeline?.timeline?.instructions ?? [];
  for (const instruction of instructions) {
    const entries = instruction.entries ?? [];
    for (const entry of entries) {
      const entryContent = entry.content;
      if (!entryContent) continue;
      if (entryContent.cursorType === "Bottom") {
        bottomCursor = entryContent.value;
        continue;
      } else if (entryContent.cursorType === "Top") {
        topCursor = entryContent.value;
        continue;
      }
      const idStr = entry.entryId;
      if (!idStr.startsWith("tweet") && !idStr.startsWith("list-conversation")) {
        continue;
      }
      if (entryContent.itemContent) {
        parseAndPush(tweets, entryContent.itemContent, idStr);
      } else if (entryContent.items) {
        for (const contentItem of entryContent.items) {
          if (contentItem.item && contentItem.item.itemContent && contentItem.entryId) {
            parseAndPush(
              tweets,
              contentItem.item.itemContent,
              contentItem.entryId.split("tweet-")[1]
            );
          }
        }
      }
    }
  }
  return { tweets, next: bottomCursor, previous: topCursor };
}

addApiFeatures({
  interactive_text_enabled: true,
  longform_notetweets_inline_media_enabled: false,
  responsive_web_text_conversations_enabled: false,
  tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: false,
  vibe_api_enabled: false
});
async function fetchTweets(userId, maxTweets, cursor, auth) {
  if (maxTweets > 200) {
    maxTweets = 200;
  }
  const userTweetsRequest = apiRequestFactory.createUserTweetsRequest();
  userTweetsRequest.variables.userId = userId;
  userTweetsRequest.variables.count = maxTweets;
  userTweetsRequest.variables.includePromotedContent = false;
  if (cursor != null && cursor != "") {
    userTweetsRequest.variables["cursor"] = cursor;
  }
  const res = await requestApi(
    userTweetsRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return parseTimelineTweetsV2(res.value);
}
async function fetchTweetsAndReplies(userId, maxTweets, cursor, auth) {
  if (maxTweets > 40) {
    maxTweets = 40;
  }
  const userTweetsRequest = apiRequestFactory.createUserTweetsAndRepliesRequest();
  userTweetsRequest.variables.userId = userId;
  userTweetsRequest.variables.count = maxTweets;
  userTweetsRequest.variables.includePromotedContent = false;
  if (cursor != null && cursor != "") {
    userTweetsRequest.variables["cursor"] = cursor;
  }
  const res = await requestApi(
    userTweetsRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return parseTimelineTweetsV2(res.value);
}
async function fetchListTweets(listId, maxTweets, cursor, auth) {
  if (maxTweets > 200) {
    maxTweets = 200;
  }
  const listTweetsRequest = apiRequestFactory.createListTweetsRequest();
  listTweetsRequest.variables.listId = listId;
  listTweetsRequest.variables.count = maxTweets;
  if (cursor != null && cursor != "") {
    listTweetsRequest.variables["cursor"] = cursor;
  }
  const res = await requestApi(
    listTweetsRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return parseListTimelineTweets(res.value);
}
function getTweets(user, maxTweets, auth) {
  return getTweetTimeline(user, maxTweets, async (q, mt, c) => {
    const userIdRes = await getUserIdByScreenName(q, auth);
    if (!userIdRes.success) {
      throw userIdRes.err;
    }
    const { value: userId } = userIdRes;
    return fetchTweets(userId, mt, c, auth);
  });
}
function getTweetsByUserId(userId, maxTweets, auth) {
  return getTweetTimeline(userId, maxTweets, (q, mt, c) => {
    return fetchTweets(q, mt, c, auth);
  });
}
function getTweetsAndReplies(user, maxTweets, auth) {
  return getTweetTimeline(user, maxTweets, async (q, mt, c) => {
    const userIdRes = await getUserIdByScreenName(q, auth);
    if (!userIdRes.success) {
      throw userIdRes.err;
    }
    const { value: userId } = userIdRes;
    return fetchTweetsAndReplies(userId, mt, c, auth);
  });
}
function getTweetsAndRepliesByUserId(userId, maxTweets, auth) {
  return getTweetTimeline(userId, maxTweets, (q, mt, c) => {
    return fetchTweetsAndReplies(q, mt, c, auth);
  });
}
async function fetchLikedTweets(userId, maxTweets, cursor, auth) {
  if (!auth.isLoggedIn()) {
    throw new Error("Scraper is not logged-in for fetching liked tweets.");
  }
  if (maxTweets > 200) {
    maxTweets = 200;
  }
  const userTweetsRequest = apiRequestFactory.createUserLikedTweetsRequest();
  userTweetsRequest.variables.userId = userId;
  userTweetsRequest.variables.count = maxTweets;
  userTweetsRequest.variables.includePromotedContent = false;
  if (cursor != null && cursor != "") {
    userTweetsRequest.variables["cursor"] = cursor;
  }
  const res = await requestApi(
    userTweetsRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  return parseTimelineTweetsV2(res.value);
}
function getLikedTweets(user, maxTweets, auth) {
  return getTweetTimeline(user, maxTweets, async (q, mt, c) => {
    const userIdRes = await getUserIdByScreenName(q, auth);
    if (!userIdRes.success) {
      throw userIdRes.err;
    }
    const { value: userId } = userIdRes;
    return fetchLikedTweets(userId, mt, c, auth);
  });
}
async function getTweetWhere(tweets, query) {
  const isCallback = typeof query === "function";
  for await (const tweet of tweets) {
    const matches = isCallback ? await query(tweet) : checkTweetMatches(tweet, query);
    if (matches) {
      return tweet;
    }
  }
  return null;
}
async function getTweetsWhere(tweets, query) {
  const isCallback = typeof query === "function";
  const filtered = [];
  for await (const tweet of tweets) {
    const matches = isCallback ? query(tweet) : checkTweetMatches(tweet, query);
    if (!matches) continue;
    filtered.push(tweet);
  }
  return filtered;
}
function checkTweetMatches(tweet, options) {
  return Object.keys(options).every((k) => {
    const key = k;
    return tweet[key] === options[key];
  });
}
async function getLatestTweet(user, includeRetweets, max, auth) {
  const timeline = getTweets(user, max, auth);
  return max === 1 ? (await timeline.next()).value : await getTweetWhere(timeline, { isRetweet: includeRetweets });
}
async function getTweet(id, auth) {
  const tweetDetailRequest = apiRequestFactory.createTweetDetailRequest();
  tweetDetailRequest.variables.focalTweetId = id;
  const res = await requestApi(
    tweetDetailRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  if (!res.value) {
    return null;
  }
  const tweets = parseThreadedConversation(res.value);
  return tweets.find((tweet) => tweet.id === id) ?? null;
}
async function getTweetAnonymous(id, auth) {
  const tweetResultByRestIdRequest = apiRequestFactory.createTweetResultByRestIdRequest();
  tweetResultByRestIdRequest.variables.tweetId = id;
  const res = await requestApi(
    tweetResultByRestIdRequest.toRequestUrl(),
    auth
  );
  if (!res.success) {
    throw res.err;
  }
  if (!res.value.data) {
    return null;
  }
  return parseTimelineEntryItemContentRaw(res.value.data, id);
}

const twUrl = "https://twitter.com";
class Scraper {
  /**
   * Creates a new Scraper object.
   * - Scrapers maintain their own guest tokens for Twitter's internal API.
   * - Reusing Scraper objects is recommended to minimize the time spent authenticating unnecessarily.
   */
  constructor(options) {
    this.options = options;
    this.token = bearerToken;
    this.useGuestAuth();
  }
  /**
   * Initializes auth properties using a guest token.
   * Used when creating a new instance of this class, and when logging out.
   * @internal
   */
  useGuestAuth() {
    this.auth = new TwitterGuestAuth(this.token, this.getAuthOptions());
    this.authTrends = new TwitterGuestAuth(this.token, this.getAuthOptions());
  }
  /**
   * Fetches a Twitter profile.
   * @param username The Twitter username of the profile to fetch, without an `@` at the beginning.
   * @returns The requested {@link Profile}.
   */
  async getProfile(username) {
    const res = await getProfile(username, this.auth);
    return this.handleResponse(res);
  }
  /**
   * Fetches the user ID corresponding to the provided screen name.
   * @param screenName The Twitter screen name of the profile to fetch.
   * @returns The ID of the corresponding account.
   */
  async getUserIdByScreenName(screenName) {
    const res = await getUserIdByScreenName(screenName, this.auth);
    return this.handleResponse(res);
  }
  /**
   * Fetches tweets from Twitter.
   * @param query The search query. Any Twitter-compatible query format can be used.
   * @param maxTweets The maximum number of tweets to return.
   * @param includeReplies Whether or not replies should be included in the response.
   * @param searchMode The category filter to apply to the search. Defaults to `Top`.
   * @returns An {@link AsyncGenerator} of tweets matching the provided filters.
   */
  searchTweets(query, maxTweets, searchMode = SearchMode.Top) {
    return searchTweets(query, maxTweets, searchMode, this.auth);
  }
  /**
   * Fetches profiles from Twitter.
   * @param query The search query. Any Twitter-compatible query format can be used.
   * @param maxProfiles The maximum number of profiles to return.
   * @returns An {@link AsyncGenerator} of tweets matching the provided filter(s).
   */
  searchProfiles(query, maxProfiles) {
    return searchProfiles(query, maxProfiles, this.auth);
  }
  /**
   * Fetches tweets from Twitter.
   * @param query The search query. Any Twitter-compatible query format can be used.
   * @param maxTweets The maximum number of tweets to return.
   * @param includeReplies Whether or not replies should be included in the response.
   * @param searchMode The category filter to apply to the search. Defaults to `Top`.
   * @param cursor The search cursor, which can be passed into further requests for more results.
   * @returns A page of results, containing a cursor that can be used in further requests.
   */
  fetchSearchTweets(query, maxTweets, searchMode, cursor) {
    return fetchSearchTweets(query, maxTweets, searchMode, this.auth, cursor);
  }
  /**
   * Fetches profiles from Twitter.
   * @param query The search query. Any Twitter-compatible query format can be used.
   * @param maxProfiles The maximum number of profiles to return.
   * @param cursor The search cursor, which can be passed into further requests for more results.
   * @returns A page of results, containing a cursor that can be used in further requests.
   */
  fetchSearchProfiles(query, maxProfiles, cursor) {
    return fetchSearchProfiles(query, maxProfiles, this.auth, cursor);
  }
  /**
   * Fetches list tweets from Twitter.
   * @param listId The list id
   * @param maxTweets The maximum number of tweets to return.
   * @param cursor The search cursor, which can be passed into further requests for more results.
   * @returns A page of results, containing a cursor that can be used in further requests.
   */
  fetchListTweets(listId, maxTweets, cursor) {
    return fetchListTweets(listId, maxTweets, cursor, this.auth);
  }
  /**
   * Fetch the profiles a user is following
   * @param userId The user whose following should be returned
   * @param maxProfiles The maximum number of profiles to return.
   * @returns An {@link AsyncGenerator} of following profiles for the provided user.
   */
  getFollowing(userId, maxProfiles) {
    return getFollowing(userId, maxProfiles, this.auth);
  }
  /**
   * Fetch the profiles that follow a user
   * @param userId The user whose followers should be returned
   * @param maxProfiles The maximum number of profiles to return.
   * @returns An {@link AsyncGenerator} of profiles following the provided user.
   */
  getFollowers(userId, maxProfiles) {
    return getFollowers(userId, maxProfiles, this.auth);
  }
  /**
   * Fetches following profiles from Twitter.
   * @param userId The user whose following should be returned
   * @param maxProfiles The maximum number of profiles to return.
   * @param cursor The search cursor, which can be passed into further requests for more results.
   * @returns A page of results, containing a cursor that can be used in further requests.
   */
  fetchProfileFollowing(userId, maxProfiles, cursor) {
    return fetchProfileFollowing(userId, maxProfiles, this.auth, cursor);
  }
  /**
   * Fetches profile followers from Twitter.
   * @param userId The user whose following should be returned
   * @param maxProfiles The maximum number of profiles to return.
   * @param cursor The search cursor, which can be passed into further requests for more results.
   * @returns A page of results, containing a cursor that can be used in further requests.
   */
  fetchProfileFollowers(userId, maxProfiles, cursor) {
    return fetchProfileFollowers(userId, maxProfiles, this.auth, cursor);
  }
  /**
   * Fetches the current trends from Twitter.
   * @returns The current list of trends.
   */
  getTrends() {
    return getTrends(this.authTrends);
  }
  /**
   * Fetches tweets from a Twitter user.
   * @param user The user whose tweets should be returned.
   * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
   * @returns An {@link AsyncGenerator} of tweets from the provided user.
   */
  getTweets(user, maxTweets = 200) {
    return getTweets(user, maxTweets, this.auth);
  }
  /**
   * Fetches liked tweets from a Twitter user. Requires authentication.
   * @param user The user whose likes should be returned.
   * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
   * @returns An {@link AsyncGenerator} of liked tweets from the provided user.
   */
  getLikedTweets(user, maxTweets = 200) {
    return getLikedTweets(user, maxTweets, this.auth);
  }
  /**
   * Fetches tweets from a Twitter user using their ID.
   * @param userId The user whose tweets should be returned.
   * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
   * @returns An {@link AsyncGenerator} of tweets from the provided user.
   */
  getTweetsByUserId(userId, maxTweets = 200) {
    return getTweetsByUserId(userId, maxTweets, this.auth);
  }
  /**
   * Fetches tweets and replies from a Twitter user.
   * @param user The user whose tweets should be returned.
   * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
   * @returns An {@link AsyncGenerator} of tweets from the provided user.
   */
  getTweetsAndReplies(user, maxTweets = 200) {
    return getTweetsAndReplies(user, maxTweets, this.auth);
  }
  /**
   * Fetches tweets and replies from a Twitter user using their ID.
   * @param userId The user whose tweets should be returned.
   * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
   * @returns An {@link AsyncGenerator} of tweets from the provided user.
   */
  getTweetsAndRepliesByUserId(userId, maxTweets = 200) {
    return getTweetsAndRepliesByUserId(userId, maxTweets, this.auth);
  }
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
  getTweetWhere(tweets, query) {
    return getTweetWhere(tweets, query);
  }
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
  getTweetsWhere(tweets, query) {
    return getTweetsWhere(tweets, query);
  }
  /**
   * Fetches the most recent tweet from a Twitter user.
   * @param user The user whose latest tweet should be returned.
   * @param includeRetweets Whether or not to include retweets. Defaults to `false`.
   * @returns The {@link Tweet} object or `null`/`undefined` if it couldn't be fetched.
   */
  getLatestTweet(user, includeRetweets = false, max = 200) {
    return getLatestTweet(user, includeRetweets, max, this.auth);
  }
  /**
   * Fetches a single tweet.
   * @param id The ID of the tweet to fetch.
   * @returns The {@link Tweet} object, or `null` if it couldn't be fetched.
   */
  getTweet(id) {
    if (this.auth instanceof TwitterUserAuth) {
      return getTweet(id, this.auth);
    } else {
      return getTweetAnonymous(id, this.auth);
    }
  }
  /**
   * Returns if the scraper has a guest token. The token may not be valid.
   * @returns `true` if the scraper has a guest token; otherwise `false`.
   */
  hasGuestToken() {
    return this.auth.hasToken() || this.authTrends.hasToken();
  }
  /**
   * Returns if the scraper is logged in as a real user.
   * @returns `true` if the scraper is logged in with a real user account; otherwise `false`.
   */
  async isLoggedIn() {
    return await this.auth.isLoggedIn() && await this.authTrends.isLoggedIn();
  }
  /**
   * Login to Twitter as a real Twitter account. This enables running
   * searches.
   * @param username The username of the Twitter account to login with.
   * @param password The password of the Twitter account to login with.
   * @param email The email to log in with, if you have email confirmation enabled.
   * @param twoFactorSecret The secret to generate two factor authentication tokens with, if you have two factor authentication enabled.
   */
  async login(username, password, email, twoFactorSecret) {
    const userAuth = new TwitterUserAuth(this.token, this.getAuthOptions());
    await userAuth.login(username, password, email, twoFactorSecret);
    this.auth = userAuth;
    this.authTrends = userAuth;
  }
  /**
   * Log out of Twitter.
   */
  async logout() {
    await this.auth.logout();
    await this.authTrends.logout();
    this.useGuestAuth();
  }
  /**
   * Retrieves all cookies for the current session.
   * @returns All cookies for the current session.
   */
  async getCookies() {
    return await this.authTrends.cookieJar().getCookies(
      typeof document !== "undefined" ? document.location.toString() : twUrl
    );
  }
  /**
   * Set cookies for the current session.
   * @param cookies The cookies to set for the current session.
   */
  async setCookies(cookies) {
    const userAuth = new TwitterUserAuth(this.token, this.getAuthOptions());
    for (const cookie of cookies) {
      await userAuth.cookieJar().setCookie(cookie, twUrl);
    }
    this.auth = userAuth;
    this.authTrends = userAuth;
  }
  /**
   * Clear all cookies for the current session.
   */
  async clearCookies() {
    await this.auth.cookieJar().removeAllCookies();
    await this.authTrends.cookieJar().removeAllCookies();
  }
  /**
   * Sets the optional cookie to be used in requests.
   * @param _cookie The cookie to be used in requests.
   * @deprecated This function no longer represents any part of Twitter's auth flow.
   * @returns This scraper instance.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  withCookie(_cookie) {
    console.warn(
      "Warning: Scraper#withCookie is deprecated and will be removed in a later version. Use Scraper#login or Scraper#setCookies instead."
    );
    return this;
  }
  /**
   * Sets the optional CSRF token to be used in requests.
   * @param _token The CSRF token to be used in requests.
   * @deprecated This function no longer represents any part of Twitter's auth flow.
   * @returns This scraper instance.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  withXCsrfToken(_token) {
    console.warn(
      "Warning: Scraper#withXCsrfToken is deprecated and will be removed in a later version."
    );
    return this;
  }
  getAuthOptions() {
    return {
      fetch: this.options?.fetch,
      transform: this.options?.transform
    };
  }
  handleResponse(res) {
    if (!res.success) {
      throw res.err;
    }
    return res.value;
  }
}

const ORIGINAL_CIPHERS = tls.DEFAULT_CIPHERS;
const TOP_N_SHUFFLE = 8;
const shuffleArray = (array) => {
  for (let i = array.length - 1; i > 0; i--) {
    const j = node_crypto.randomBytes(4).readUint32LE() % array.length;
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
};
const randomizeCiphers = () => {
  do {
    const cipherList = ORIGINAL_CIPHERS.split(":");
    const shuffled = shuffleArray(cipherList.slice(0, TOP_N_SHUFFLE));
    const retained = cipherList.slice(TOP_N_SHUFFLE);
    tls.DEFAULT_CIPHERS = [...shuffled, ...retained].join(":");
  } while (tls.DEFAULT_CIPHERS === ORIGINAL_CIPHERS);
};

class NodePlatform {
  randomizeCiphers() {
    randomizeCiphers();
    return Promise.resolve();
  }
}
const platform = new NodePlatform();

var index = /*#__PURE__*/Object.freeze({
  __proto__: null,
  platform: platform
});

exports.Scraper = Scraper;
exports.SearchMode = SearchMode;
//# sourceMappingURL=index.cjs.map
