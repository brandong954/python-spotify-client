import string
import random
import base64
import os
from lib.helpers import make_request, get_json_from_response
from datetime import datetime, timedelta
from lib.logger import log, log_error, log_debug, log_verbose, log_success
from flask import url_for, redirect, request

SPOTIFY_CLIENT_ID = None
SPOTIFY_AUTHORIZATION = None
SPOTIFY_CALLBACK_URL = None
SPOTIFY_AUTH_REDIRECT_URL = None
SPOTIFY_API_URI = "https://api.spotify.com/v1"
SPOTIFY_ACCOUNTS_URI = "https://accounts.spotify.com"
SPOTIFY_TOKEN_API_ENDPOINT = "%s/api/token" % SPOTIFY_ACCOUNTS_URI
SPOTIFY_USERS = {}

def init_spotify(spotify_client_id=None, spotify_client_secret=None, spotify_callback_url=None, spotify_auth_redirect_url=None):
    global SPOTIFY_CLIENT_ID, SPOTIFY_AUTHORIZATION, SPOTIFY_CALLBACK_URL, SPOTIFY_AUTH_REDIRECT_URL

    if spotify_client_id and spotify_client_secret and spotify_callback_url and spotify_auth_redirect_url:
        SPOTIFY_CLIENT_ID = spotify_client_id
        SPOTIFY_CALLBACK_URL = spotify_callback_url
        SPOTIFY_AUTH_REDIRECT_URL = spotify_auth_redirect_url
    else:
        try:
            SPOTIFY_CLIENT_ID = os.environ['SPOTIFY_CLIENT_ID']
            spotify_client_secret = os.environ['SPOTIFY_CLIENT_SECRET']
            SPOTIFY_CALLBACK_URL = os.environ['SPOTIFY_CALLBACK_URL']
            SPOTIFY_AUTH_REDIRECT_URL = os.environ['SPOTIFY_AUTH_REDIRECT_URL']
        except KeyError:
            log_error("Environment variables SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_CALLBACK_URL, and SPOTIFY_AUTH_REDIRECT_URL must be set if not passed to set_app_config().")

    log_debug("SPOTIFY_CLIENT_ID: %s" % SPOTIFY_CLIENT_ID)
    log_debug("SPOTIFY_CLIENT_SECRET: %s" % spotify_client_secret)
    log_debug("SPOTIFY_CALLBACK_URL: %s" % SPOTIFY_CALLBACK_URL)
    log_debug("SPOTIFY_AUTH_REDIRECT_URL: %s" % SPOTIFY_AUTH_REDIRECT_URL)

    SPOTIFY_AUTHORIZATION = base64.b64encode(("%s:%s" % (SPOTIFY_CLIENT_ID, spotify_client_secret)).encode()).decode()

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def spotify_callback():
    log("Spotify calling back...")

    state = request.args.get("state")
    log_debug("Spotify returned user state: %s" % state)

    spotify_user = SPOTIFY_USERS.get(state)

    if spotify_user is not None:
        spotify_user.code = request.args.get("code")
        log_debug("Spotify returned user code: %s" % spotify_user.code)

        if spotify_user.code is None:
            error = request.args.get("error")
            error_message = "Error authorizing spotify user. Code: %s" % error
            log_error(error_message)
        else:
            spotify_user.set_spotify_user_object()
    else:
        log_debug("Spotify callback endpoint requested with invalid state.")

    return redirect(SPOTIFY_AUTH_REDIRECT_URL)

# TODO keys need try/except logic so we can see when they change easily instead of just using ".get()"
# We should be settting up class params for them as well instead of getting them on the fly from the returned spotify object.
# After doing so, refactor the functions where these get instantiated as objects to not contain the various
# try/except logic.
class SpotifyArtist:
    spotify_artist_object = None

    def __init__(self, spotify_artist_object):
        self.spotify_artist_object = spotify_artist_object

    def get_uri(self):
        return self.spotify_artist_object['uri']

    def get_name(self):
        return self.spotify_artist_object['name']

    def get_id(self):
        return self.spotify_artist_object['id']

    def get_genres(self):
        spotify_artist_genres = set(self.spotify_artist_object['genres'])
        return spotify_artist_genres

class SpotifyAlbum:
    spotify_album_object = None

    def __init__(self, spotify_album_object):
        self.spotify_album_object = spotify_album_object

    def get_uri(self):
        return self.spotify_album_object['uri']

    def get_name(self):
        return self.spotify_album_object['name']

    def get_id(self):
        return self.spotify_album_object['id']

    def get_popularity(self):
        return self.spotify_album_object['popularity']

    def get_type(self):
        return self.spotify_album_object['album_type']

    def get_genres(self):
        spotify_album_genres = self.spotify_album_object['genres']
        log_debug("Spotify genres for album '%s': %s" %  (self.get_name(), spotify_album_genres))
        return spotify_album_genres

# TODO keys need try/except logic so we can see when they change easily instead of just using ".get()"
class SpotifyTrack:
    spotify_track_object = None

    def __init__(self, spotify_track_object):
        self.spotify_track_object = spotify_track_object

    def get_track_object(self):
        return self.spotify_track_object

    def get_uri(self):
        return self.spotify_track_object['uri']

    def get_name(self):
        return self.spotify_track_object['name']

    def is_local(self):
        return self.spotify_track_object['is_local']

    def get_artist_name(self):
        return self.spotify_track_object['artists'][0]['name']

    def get_artist_id(self):
        return self.spotify_track_object['artists'][0]['id']

    def get_album(self):
        return SpotifyAlbum(self.spotify_track_object['album'])

    def get_popularity(self):
        return self.spotify_track_object['popularity']

# TODO keys need try/except logic so we can see when they change easily instead of just using ".get()"
class SpotifyPlaylist:
    spotify_playlist_object = None

    def __init__(self, spotify_playlist_object):
        self.spotify_playlist_object = spotify_playlist_object

    def get_id(self):
        return self.spotify_playlist_object['id']

    def get_name(self):
        return self.spotify_playlist_object['name']

    def get_total_tracks(self):
        return self.spotify_playlist_object['tracks']['total']

    def get_owner_id(self):
        return self.spotify_playlist_object['owner']['id']

    def is_empty(self):
        return self.get_total_tracks() == 0

class SpotifyUser:
    code = None
    state = None
    access_token = None
    token_type = None
    scope = None
    expiration_date = None
    refresh_token = None
    spotify_user_object = None

    def __init__(self):
        # TODO this should not be random
        self.state = id_generator(12)
        #self.authorize()
        SPOTIFY_USERS[self.state] = self

    def authorize(self, scope="user-read-private user-read-email"):
        self.scope = scope
        log("Authorizing Spotify user ...")
        response_type = "code"
        spotify_authorization_endpoint = "%s/authorize" % SPOTIFY_ACCOUNTS_URI
        uri = "%s?client_id=%s&response_type=%s&redirect_uri=%s&scope=%s&state=%s" \
            % (spotify_authorization_endpoint, SPOTIFY_CLIENT_ID, response_type, SPOTIFY_CALLBACK_URL, self.scope, self.state)
        log_debug("Redirect to Spotify authorization service: %s" % uri)
        return redirect(uri)

    def set_access_token(self):
        headers = {'Authorization': "Basic %s" % SPOTIFY_AUTHORIZATION}
        grant_type_data_key = 'grant_type'
        refresh_token_grant_type = 'refresh_token'
        authorization_code_grant_type = 'authorization_code'
        client_credentials_grant_type = 'client_credentials'

        if self.refresh_token:
            data = {grant_type_data_key:refresh_token_grant_type, 'refresh_token':self.refresh_token}
        elif self.code:
            # No redirection actually occurs, but Spotify uses it for validation purposes.
            data = {grant_type_data_key:authorization_code_grant_type, 'code':self.code, 'redirect_uri':SPOTIFY_CALLBACK_URL}
        else:
            data = {grant_type_data_key:client_credentials_grant_type}

        log_debug("Request Header: %s" % headers)
        log_debug("Request Data: %s" % data)

        response = make_request(SPOTIFY_TOKEN_API_ENDPOINT, method="POST", headers=headers, data=data)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            error_message = "Unable to get Spotify user token!"
            log_error("%s\n%s" % (error_message, response_obj))
            return False

        log_debug("Response Header: %s" % response.headers)
        log_debug("Response Data: %s" % response_obj)

        try:
            self.access_token = response_obj['access_token']
            self.token_type = response_obj['token_type']
            self.expiration_date = datetime.now() + timedelta(seconds=response_obj['expires_in'])
            if data[grant_type_data_key] != client_credentials_grant_type:
                self.scope = response_obj['scope']
            if data[grant_type_data_key] == authorization_code_grant_type:
                self.refresh_token = response_obj['refresh_token']
        except KeyError as key_error:
            error_message = "Unable to authorize user due to missing key %s in response." % key_error
            log_error(error_message)
            return False

        return True

    def _validate_access_token(func):

        def validate(self, *args, **kwargs):
            if not self.access_token or (self.expiration_date and self.expiration_date < datetime.now()):
                self.set_access_token()
            return func(self, *args, **kwargs)

        return validate

    # TODO keys need try/except logic so we can see when they change easily instead of just using ".get()"
    def get_id(self):
        return self.spotify_user_object['id']

    @_validate_access_token
    def set_spotify_user_object(self):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        response = make_request("%s/me" % SPOTIFY_API_URI, headers=headers)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            error_message="Unable to get Spotify user info!"
            log_error("%s\n%s" % (error_message, response_obj))
            return False
        else:
            self.spotify_user_object = response_obj

        log_debug("User profile: %s" % self.spotify_user_object)

        return True

    @_validate_access_token
    def add_tracks_to_playlist(self, playlist_id, track_URIs):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token), 'Content-Type': 'application/json'}
        data = {'uris': track_URIs}
        url = "%s/playlists/%s/tracks" % (SPOTIFY_API_URI, playlist_id)

        log_verbose("Adding tracks to playlist '%s': %s" % (playlist_id, data))

        # The response body contains a snapshot_id in JSON format. The snapshot_id can be used to identify your playlist version in 
        # future requests. On error, the header status code is an error code and the response body contains an error object. T
        response = make_request(url, method="POST", headers=headers, data=data)
        response_obj = get_json_from_response(response)

        if response.status_code != 201:
            raise Exception("Failed to add tracks to playlist: %s" % response_obj)

        return response_obj

    @_validate_access_token
    def create_playlist(self, name, description=""):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token), 'Content-Type': 'application/json'}
        data = {'name': name, 'description': description}
        url = "%s/users/%s/playlists" % (SPOTIFY_API_URI, self.get_id())

        log("Creating playlist: %s" % data)

        # response will be the created playlist object if success, otherwise it will be an error object
        response = make_request(url, method="POST", headers=headers, data=data)
        response_obj = get_json_from_response(response)

        if response.status_code != 200 and response.status_code != 201:
            raise Exception("Failed to create playlist: %s" % response_obj)

        return SpotifyPlaylist(response_obj)

    @_validate_access_token
    def get_artist(self, artist_id):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/artists/%s" % (SPOTIFY_API_URI, artist_id)

        log_verbose("Getting artist: %s" % artist_id)

        # response will be the artist object if success, otherwise it will be an error object
        response = make_request(url, headers=headers)
        response_obj = get_json_from_response(response)

        if response.status_code == 404:
            log_debug("Unable to locate Spotify artist for artist_id '%s'! %s" % (artist_id, response_obj))
        elif response.status_code != 200:
            raise Exception("Failed to get artist '%s': %s" % (artist_id, response_obj))

        return SpotifyArtist(response_obj)

    @_validate_access_token
    def get_artist_albums(self, artist_id):
        albums = []
        limit = 50
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/artists/%s/albums?limit=%d&include_groups=album" % (SPOTIFY_API_URI, artist_id, limit)

        log_debug("Getting Spotify albums for '%s'..." % artist_id)

        while url is not None:
            response = make_request(url, headers=headers)
            response_obj = get_json_from_response(response)

            if response.status_code != 200:
                error_message="Unable to get albums for artist_id '%s'!" % artist_id
                raise Exception("%s\n%s" % (error_message, response_obj))

            log_verbose("Spotify's response: %s" % response_obj)

            try:
                items = response_obj["items"]
                for item in items:
                    albums.append(self.get_album(item['id']))
                url = response_obj['next']
            except KeyError as key_error:
                error_message="Unable to get artist's albums due to missing key %s in response." % key_error
                raise Exception(error_message)

        log_verbose(albums)

        return albums

    @_validate_access_token
    def get_album(self, album_id):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/albums/%s" % (SPOTIFY_API_URI, album_id)

        log_verbose("Getting album: %s" % album_id)

        # response will be the album object if success, otherwise it will be an error object
        response = make_request(url, headers=headers)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            raise Exception("Failed to get album '%s': %s" % (album_id, response_obj))

        return SpotifyAlbum(response_obj)

    @_validate_access_token
    def get_playlist(self, playlist_id):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/playlists/%s" % (SPOTIFY_API_URI, playlist_id)

        log_verbose("Getting playlist: %s" % playlist_id)

        # response will be the playlist object if success, otherwise it will be an error object
        response = make_request(url, headers=headers)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            raise Exception("Failed to get playlist '%s': %s" % (playlist_id, response_obj))

        return SpotifyPlaylist(response_obj)

    @_validate_access_token
    def get_playlists(self):
        playlists = []
        limit = 50
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/me/playlists?limit=%d" % (SPOTIFY_API_URI, limit)

        while url is not None:
            response = make_request(url, headers=headers)
            response_obj = get_json_from_response(response)

            if response.status_code != 200:
                error_message="Unable to get Spotify user's playlists!"
                raise Exception("%s\n%s" % (error_message, response_obj))

            log_verbose("Spotify's response: %s" % response_obj)

            try:
                items = response_obj["items"]
                for item in items:
                    playlists.append(SpotifyPlaylist(item))
                url = response_obj['next']
            except KeyError as key_error:
                error_message="Unable to get user's playlists due to missing key %s in response." % key_error
                raise Exception(error_message)

        log_verbose(playlists)

        return playlists

    # Although this function could technically return all tracks within a given playlist,
    # processing more than 100 tracks at a time is a bad idea due to running out of memory. Instead, iterate on this function
    # using `offset` when possible.
    @_validate_access_token
    def get_tracks_from_playlist(self, playlist_id, offset=0, limit=100):
        tracks = []
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        fields = "uri, next,items(track(uri,is_local,name,href,album(name,href,id),id,artists(name,href,id)))"

        # If limit is not between Spotify's allowable limit range, use Spotify's default limit for the request.
        if limit > 100 or limit < 1:
            spotify_limit = 100
        else:
            spotify_limit = limit

        url = "%s/playlists/%s/tracks?fields=%s&offset=%d&limit=%d" % (SPOTIFY_API_URI, playlist_id, fields, offset, spotify_limit)

        while url is not None and len(tracks) < limit:
            response = make_request(url, headers=headers)
            response_obj = get_json_from_response(response)

            if response.status_code != 200:
                error_message="Unable to get tracks for playlist!"
                raise Exception("%s\n%s" % (error_message, response_obj))

            log_verbose("Spotify's response: %s" % response_obj)

            try:
                items = response_obj["items"]
                for item in items:
                    if len(tracks) < limit:
                        tracks.append(SpotifyTrack(item['track']))
                    else:
                        break
                url = response_obj['next']
            except KeyError as key_error:
                error_message="Unable to get tracks for playlist_id '%s' due to missing key %s in response." % (playlist_id, key_error)
                raise Exception(error_message)

        log_verbose(tracks)

        assert len(tracks) <= limit

        return tracks

    @_validate_access_token
    def delete_tracks_from_playlist(self, playlist_id, track_URIs):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token), 'Content-Type': 'application/json'}
        url = "%s/playlists/%s/tracks" % (SPOTIFY_API_URI, playlist_id)

        data = {'tracks': []}

        for track_URI in track_URIs:
            data['tracks'].append({'uri': track_URI})

        log_debug("Deleting tracks from playlist '%s': %s" % (playlist_id, data))

        response = make_request(url, method="DELETE", headers=headers, data=data)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            error_message="Unable to delete tracks from playlist!"
            raise Exception("%s\n%s" % (error_message, response_obj))

    @_validate_access_token
    def unfollow_playlist(self, playlist_id):
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/playlists/%s/followers" % (SPOTIFY_API_URI, playlist_id)

        playlist_object = self.get_playlist(playlist_id)

        log_debug("Unfollowing playlist: %s" % {playlist_id: playlist_object.get_name()})

        # On success, the HTTP status code in the response header is 200 OK and the response body is empty.
        # On error, the header status code is an error code and the response body contains an error object.
        response = make_request(url, method="DELETE", headers=headers)

        if response.status_code != 200:
            response_obj = get_json_from_response(response)
            error_message="Unable to unfollow playlist!"
            raise Exception("%s\n%s" % (error_message, response_obj))

    @_validate_access_token
    def get_most_popular_artist(self, artist_name):
        most_popular_spotify_artist = None
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/search?q=\"%s\"&type=artist&limit=50" % (SPOTIFY_API_URI, artist_name)

        while url is not None:
            response = make_request(url, headers=headers)
            response_obj = get_json_from_response(response)

            if response.status_code != 200:
                error_message="Unable to queary Spotify for artists!"
                raise Exception("%s\n%s" % (error_message, response_obj))

            log_verbose("Spotify's response: %s" % response_obj)

            # popularity can be 0 for an artist
            max_popularity_count = -1
            try:
                artists = response_obj["artists"]
                for artist in artists['items']:
                    if artist['name'] == artist_name and artist['popularity'] > max_popularity_count:
                        most_popular_spotify_artist = SpotifyArtist(artist)
                url = response_obj['next']
            except KeyError as key_error:
                error_message="Unable to get most popular Spotify artist for '%s' due to missing key %s in response." % (artist_name, key_error)
                raise Exception(error_message)

        if not most_popular_spotify_artist:
            log_debug("Unable to find a popular Spotify artist for '%s'." % artist_name)

        return most_popular_spotify_artist

    @_validate_access_token
    def get_artist_top_tracks(self, artist_id):
        top_tracks =[]
        headers = {'Authorization': "%s %s" % (self.token_type, self.access_token)}
        url = "%s/artists/%s/top-tracks?country=us" % (SPOTIFY_API_URI, artist_id)
        response = make_request(url, headers=headers)
        response_obj = get_json_from_response(response)

        if response.status_code != 200:
            error_message="Unable to queary Spotify for artists' top tracks!"
            raise Exception("%s\n%s" % (error_message, response_obj))

        log_verbose("Spotify's response: %s" % response_obj)

        # popularity can be 0 for an artist
        max_popularity_count = -1
        try:
            for track in response_obj["tracks"]:
                top_tracks.append(SpotifyTrack(track))
        except KeyError as key_error:
            error_message="Unable to get top tracks for artist '%s' due to missing key %s in response." % (artist_id, key_error)
            raise Exception(error_message)

        return top_tracks

    @_validate_access_token
    def get_most_popular_artist_album(self, artist_id):
        most_popular_spotify_artist_album = None
        max_count = -1
        artist_albums = self.get_artist_albums(artist_id)
        for artist_album in artist_albums:
            artist_album_popularity = artist_album.get_popularity()
            if artist_album_popularity > max_count:
                most_popular_spotify_artist_album = artist_album
                max_count = artist_album_popularity

        return most_popular_spotify_artist_album

    # Returns an album_name for artist_id based on their top tracks, preferring albums over singles
    # and compilations.
    @_validate_access_token
    def get_album_name_from_artist_top_tracks(self, artist_id):
        # popularity ranges from 0 to 100
        most_popular_spotify_track_from_album = None
        most_popular_spotify_track_not_from_album = None
        artist_top_tracks = self.get_artist_top_tracks(artist_id)
        for track in artist_top_tracks:
            album_type = track.get_album().get_type()
            if album_type == 'album':
                most_popular_spotify_track_from_album = track
                break
            elif not most_popular_spotify_track_not_from_album:
                most_popular_spotify_track_not_from_album = track

        # Return actual album names before single-based album names, if they exist.
        if most_popular_spotify_track_from_album:
            return most_popular_spotify_track_from_album.get_album().get_name()
        else:
            return most_popular_spotify_track_not_from_album.get_album().get_name()
